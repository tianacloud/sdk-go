// Loopback-only interoperability fixture for the pinned Gateway source.
// Ingress, TLS/H2, orchestration and relay are real; Control/locator and the
// byte-echo Agent are synthetic. This does not validate production databases.
use gateway_protocol::route::{ClientHello, ServerHello, ServerStatus};
use gateway_public::{
    PublicConnectService, PublicGateway, PublicLimits, PublicRequest, PublicServiceError,
    TlsMaterial,
};
use gateway_runtime::{
    agent_handshake::AgentDialer,
    locate::LocateCoordinator,
    orchestration::{
        ClockPort, ClockPortError, OrchestrationClocks, OrchestrationRequest, Orchestrator,
    },
};
use gateway_services::{
    AgentAddress, AgentHandle, AuthMode, ClockSample, EndpointAccess, EndpointId,
    EnsureActiveRequest, FakeControlAuthorization, FakeRuntimeLocator, InstanceId, LocateRequest,
    LocatedAgent, MonotonicTimeMs, PresentedToken, QuotaReason, ResolvePolicyRequest, RouteCache,
    RouteRevision, RuntimeAddress, RuntimeLocateKey, TokenResult, WallTimeMs,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const ENDPOINT: &str = "ep-01j5c9m7q2v8x4k6n3r0t1w2yz";
const INSTANCE: &str = "instance-sdk-fixture";
const RUNTIME_ADDRESS: &str = "127.0.0.1:1";
const ROUTE_REVISION: u64 = 1;
// Public test input: 32 zero bytes, never a deployment credential.
const SYNTHETIC_TOKEN: &str = "tia_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
struct FixedClock;
fn fixed_clock() -> gateway_services::ClockSnapshot {
    gateway_services::ClockSnapshot {
        sample: ClockSample {
            wall: WallTimeMs(1000),
            monotonic: MonotonicTimeMs(1000),
        },
    }
}
impl ClockPort for FixedClock {
    fn observe(&self) -> Result<gateway_services::ClockSnapshot, ClockPortError> {
        Ok(fixed_clock())
    }
}
type RuntimeTestOrchestrator = Orchestrator<FakeControlAuthorization, FakeRuntimeLocator>;

#[derive(Clone)]
struct RuntimeService {
    orchestrator: Arc<RuntimeTestOrchestrator>,
    instance_id: InstanceId,
    runtime_address: RuntimeAddress,
    route_revision: RouteRevision,
    authenticated: bool,
}

impl PublicConnectService for RuntimeService {
    fn connect<'a>(
        &'a self,
        request: PublicRequest,
        token: &'a mut PresentedToken,
        budget: Duration,
    ) -> gateway_public::ConnectFuture<'a> {
        if self.authenticated
            && token.with_raw_bytes(|raw| raw == SYNTHETIC_TOKEN.as_bytes()) == Some(false)
        {
            token.clear();
            return Box::pin(async { Err(PublicServiceError::AccessDenied) });
        }
        let orchestrator = Arc::clone(&self.orchestrator);
        let endpoint_id = request.endpoint_id().clone();
        let request_id = request.request_id().clone();
        let protocol_id = request.protocol_id();
        let channel = request.channel();
        let instance_id = self.instance_id.clone();
        let runtime_address = self.runtime_address.clone();
        let route_revision = self.route_revision;
        Box::pin(async move {
            let hello_instance = gateway_protocol::route::InstanceId::new(instance_id.as_str())
                .map_err(|_| PublicServiceError::Malformed)?;
            let hello_revision = gateway_protocol::route::RouteRevision::new(route_revision.get())
                .map_err(|_| PublicServiceError::Malformed)?;
            let hello = ClientHello::new(
                hello_instance,
                gateway_protocol::route::BranchId::new("main").unwrap(),
                hello_revision,
            )
            .with_channel(channel);
            let key = RuntimeLocateKey {
                branch_id: gateway_services::BranchId::new("main").unwrap(),
                runtime_address,
                instance_id: instance_id.clone(),
                route_revision,
            };
            let orchestration_request = OrchestrationRequest {
                channel,
                resolve: ResolvePolicyRequest {
                    request_id: request_id.clone(),
                    endpoint_id,
                },
                ensure: EnsureActiveRequest {
                    branch_id: gateway_services::BranchId::new("main").unwrap(),
                    request_id: request_id.clone(),
                    instance_id: instance_id.clone(),
                },
                locate: LocateRequest { request_id, key },
                protocol_id,
                clocks: OrchestrationClocks {
                    policy_started: fixed_clock(),
                    policy_received: fixed_clock(),
                    authorize_at: fixed_clock(),
                    before_wake: fixed_clock(),
                    before_handshake: fixed_clock(),
                    route_now: MonotonicTimeMs(1_000),
                },
            };
            let commit = orchestrator
                .connect_and_commit(&orchestration_request, token, &hello, budget)
                .await
                .map_err(PublicServiceError::from)?;
            Ok(gateway_public::CommittedSession::from_commit(commit))
        })
    }
}

async fn runtime_service_for_agent(
    agent_address: AgentAddress,
    authenticated: bool,
) -> Arc<RuntimeService> {
    let endpoint_id = EndpointId::parse(ENDPOINT).unwrap();
    let instance_id = InstanceId::new(INSTANCE).unwrap();
    let runtime_address = RuntimeAddress::new(RUNTIME_ADDRESS).unwrap();
    let route_revision = RouteRevision::new(ROUTE_REVISION).unwrap();
    let key = RuntimeLocateKey {
        branch_id: gateway_services::BranchId::new("main").unwrap(),
        runtime_address: runtime_address.clone(),
        instance_id: instance_id.clone(),
        route_revision,
    };

    let locator = FakeRuntimeLocator::default();
    locator.set_agent(
        key.clone(),
        LocatedAgent {
            key: key.clone(),
            agent_address,
        },
    );
    let route_cache = RouteCache::new(4).unwrap();
    route_cache
        .insert(
            AgentHandle {
                branch_id: gateway_services::BranchId::new("main").unwrap(),
                runtime_address: runtime_address.clone(),
                instance_id: instance_id.clone(),
                route_revision,
            },
            MonotonicTimeMs(1_000),
            20_000,
        )
        .unwrap();

    let policy = FakeControlAuthorization::default();
    let policy_response = EndpointAccess {
        endpoint_id: endpoint_id.clone(),
        instance_id: instance_id.clone(),
        branch_id: gateway_services::BranchId::new("main").unwrap(),
        auth_mode: if authenticated {
            AuthMode::TokenRequired
        } else {
            AuthMode::Disabled
        },
        token: authenticated.then_some(TokenResult {
            allowed: true,
            expire_time: -1,
            revision: 1,
        }),
    };
    policy.set_route(
        instance_id.clone(),
        AgentHandle {
            branch_id: gateway_services::BranchId::new("main").unwrap(),
            runtime_address: runtime_address.clone(),
            instance_id: instance_id.clone(),
            route_revision,
        },
    );
    policy.set_policy(endpoint_id, policy_response);

    let locator = LocateCoordinator::new(locator, 4, 4, 4).unwrap();
    let orchestrator = Orchestrator::new_with_ports(
        policy,
        locator,
        4,
        route_cache,
        AgentDialer::new(Duration::from_secs(1), Duration::from_secs(1)),
        FixedClock,
    );
    Arc::new(RuntimeService {
        orchestrator: Arc::new(orchestrator),
        instance_id: instance_id.clone(),
        runtime_address,
        route_revision,
        authenticated,
    })
}

struct ErrorService(PublicServiceError);
impl PublicConnectService for ErrorService {
    fn connect<'a>(
        &'a self,
        _: PublicRequest,
        token: &'a mut PresentedToken,
        _: Duration,
    ) -> gateway_public::ConnectFuture<'a> {
        token.clear();
        Box::pin(async move { Err(self.0) })
    }
}
async fn serve<S: PublicConnectService>(root: &std::path::Path, service: Arc<S>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let material = TlsMaterial::from_der(
        vec![std::fs::read(root.join("cert.der")).unwrap()],
        std::fs::read(root.join("key.der")).unwrap(),
    )
    .unwrap();
    let gateway = PublicGateway::from_material(
        "db.example.test",
        material,
        service,
        PublicLimits::default(),
    )
    .unwrap();
    tokio::spawn(async move {
        gateway.serve(listener).await.unwrap();
    });
    address
}
#[tokio::main]
async fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("fixture directory"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_address = AgentAddress::new(listener.local_addr().unwrap().to_string()).unwrap();
    let anonymous = runtime_service_for_agent(agent_address.clone(), false).await;
    let authenticated = runtime_service_for_agent(agent_address, true).await;
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // All database profiles use the same opaque Agent tunnel channel.
                let expected = ClientHello::new(
                    gateway_protocol::route::InstanceId::new(INSTANCE).unwrap(),
                    gateway_protocol::route::BranchId::new("main").unwrap(),
                    gateway_protocol::route::RouteRevision::new(ROUTE_REVISION).unwrap(),
                );
                let mut hello = vec![0; expected.encoded_len()];
                if stream.read_exact(&mut hello).await.is_err() {
                    return;
                }
                assert_eq!(hello, expected.encode());
                let reply = ServerHello::new(ServerStatus::Ok, ROUTE_REVISION)
                    .unwrap()
                    .encode();
                if stream.write_all(&reply).await.is_err()
                    || stream.write_all(b"HELLO").await.is_err()
                {
                    return;
                }
                let mut buffer = [0; 8192];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) => {
                            let _ = stream.write_all(b"EOF-TAIL").await;
                            let _ = stream.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    let mut ready = serde_json::Map::new();
    ready.insert(
        "endpoint".into(),
        format!("{ENDPOINT}.db.example.test").into(),
    );
    ready.insert(
        "gateway_commit".into(),
        "9f5aa69b24aa6e04112baaf8d1e17c0639fd293b".into(),
    );
    ready.insert("greeting".into(), "HELLO".into());
    ready.insert("eof_tail".into(), "EOF-TAIL".into());
    ready.insert(
        "anonymous_address".into(),
        serve(&root, anonymous).await.into(),
    );
    ready.insert(
        "token_address".into(),
        serve(&root, authenticated).await.into(),
    );
    for (name, error) in [
        (
            "AUTHORIZATION_EXPIRED",
            PublicServiceError::AuthorizationExpired,
        ),
        ("CALLER_DEADLINE", PublicServiceError::CallerDeadline),
        ("ENDPOINT_MISMATCH", PublicServiceError::EndpointMismatch),
        ("CONNECTION_LIMIT", PublicServiceError::ConnectionLimit),
        ("POLICY_UNAVAILABLE", PublicServiceError::PolicyUnavailable),
        (
            "INSTANCE_UNAVAILABLE",
            PublicServiceError::InstanceUnavailable,
        ),
        ("ACTIVATION_TIMEOUT", PublicServiceError::ActivationTimeout),
        ("MALFORMED_CONNECT", PublicServiceError::Malformed),
        (
            "quota_compute",
            PublicServiceError::QuotaExceeded(QuotaReason::Compute),
        ),
        (
            "quota_storage",
            PublicServiceError::QuotaExceeded(QuotaReason::Storage),
        ),
        (
            "quota_both",
            PublicServiceError::QuotaExceeded(QuotaReason::ComputeAndStorage),
        ),
    ] {
        ready.insert(
            name.into(),
            serve(&root, Arc::new(ErrorService(error))).await.into(),
        );
    }
    std::fs::write(
        root.join("ready.json"),
        serde_json::to_vec_pretty(&ready).unwrap(),
    )
    .unwrap();
    std::future::pending::<()>().await;
}
