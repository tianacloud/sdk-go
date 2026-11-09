// Package files provides file storage types for Tiana Functions. Create a Client
// with function.Files, function.FilesByWebApp or function.FilesFromRequest.
package files

import "github.com/tianacloud/sdk-go/internal/functionfiles"

type Client = functionfiles.Client
type ListOptions = functionfiles.ListOptions
type GetOptions = functionfiles.GetOptions
type PutOptions = functionfiles.PutOptions
type Entry = functionfiles.Entry
type Page = functionfiles.Page
type Metadata = functionfiles.Metadata
type PutReceipt = functionfiles.PutReceipt
type Capabilities = functionfiles.Capabilities
type Error = functionfiles.Error

var ErrNoWebContext = functionfiles.ErrNoWebContext
