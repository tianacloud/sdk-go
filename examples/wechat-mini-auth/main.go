// A Function backend for native mini-program application authentication.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tianacloud/sdk-go/function"
	"github.com/tianacloud/sdk-go/wechatmini"
)

func main() {
	config, err := function.ReadConfig()
	if err != nil {
		log.Fatal("cannot read Function configuration")
	}
	appID, err := config.Get("WECHAT_APP_ID")
	if err != nil {
		log.Fatal("WECHAT_APP_ID is required")
	}
	secret, err := config.Get("WECHAT_APP_SECRET")
	if err != nil {
		log.Fatal("WECHAT_APP_SECRET is required")
	}
	encodedKey, err := config.Get("APP_SESSION_KEY")
	if err != nil {
		log.Fatal("APP_SESSION_KEY is required")
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		log.Fatal("APP_SESSION_KEY must be base64-encoded random bytes")
	}
	auth, err := wechatmini.New(wechatmini.Config{AppID: appID, AppSecret: secret, SigningKey: key, SessionTTL: time.Hour})
	if err != nil {
		log.Fatal("invalid application authentication configuration")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	server := &http.Server{Addr: ":" + port, Handler: newHandler(auth), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func newHandler(auth *wechatmini.Authenticator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Code string `json:"code"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&input) != nil || input.Code == "" {
			writeJSON(w, 400, map[string]string{"error": "LOGIN_CODE_REQUIRED"})
			return
		}
		session, err := auth.Login(r.Context(), input.Code)
		if err != nil {
			var providerErr *wechatmini.ProviderError
			if errors.As(err, &providerErr) {
				writeJSON(w, 401, map[string]any{"error": "WECHAT_LOGIN_REJECTED", "provider_code": providerErr.Code})
			} else {
				writeJSON(w, 502, map[string]string{"error": "WECHAT_LOGIN_UNAVAILABLE"})
			}
			return
		}
		writeJSON(w, 200, session)
	})
	mux.Handle("GET /me", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := wechatmini.FromContext(r.Context())
		writeJSON(w, 200, map[string]any{"identity": identity})
	})))
	mux.Handle("POST /greet", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Message string `json:"message"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&input) != nil {
			writeJSON(w, 400, map[string]string{"error": "INVALID_REQUEST"})
			return
		}
		identity, _ := wechatmini.FromContext(r.Context())
		writeJSON(w, 200, map[string]any{"identity": identity, "message": input.Message, "reply": "已按服务端验证的微信身份处理请求"})
	})))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
