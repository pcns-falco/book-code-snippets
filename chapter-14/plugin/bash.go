package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hpcloud/tail"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// config represents the plugin configuration.
type config struct {
	Path string
}

// bashPlugin holds the state of the plugin.
type bashPlugin struct {
	plugins.BasePlugin
	config config
}

func (b *bashPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        "bash",
		Description: "A Plugin that reads from ~/.bash_history",
		Contact:     "github.com/falcosecurity/plugin-sdk-go/",
		Version:     "0.1.0",
		EventSource: "bash",
	}
}

func (b *bashPlugin) Init(config string) error {

	// default value
	homeDir, _ := os.UserHomeDir()
	b.config.Path = homeDir + "/.bash_history"

	// skip empty config
	if config == "" {
		return nil
	}

	// else parse the provided config
	return json.Unmarshal([]byte(config), &b.config)
}

// bashInstance holds the state of the current session.
type bashInstance struct {
	source.BaseInstance
	t      *tail.Tail
	ticker *time.Ticker
}

// Open opens the plugin source and starts a new capture session (e.g. stream
// of events), creating a new plugin instance. The state of each instance can
// be initialized here. This method is mandatory for source plugins.
func (b *bashPlugin) Open(params string) (source.Instance, error) {
	t, err := tail.TailFile(b.config.Path, tail.Config{
		Follow: true,
		Location: &tail.SeekInfo{
			Offset: 0,
			Whence: os.SEEK_END,
		},
	})
	if err != nil {
		return nil, err
	}

	return &bashInstance{
		t:      t,
		ticker: time.NewTicker(time.Millisecond * 30),
	}, nil
}

// NextBatch produces a batch of new events, and is called repeatedly by the
// framework. For source plugins, it's mandatory to specify a NextBatch method.
// The batch has a maximum size that dependes on the size of the underlying
// reusable memory buffer. A batch can be smaller than the maximum size.
func (b *bashInstance) NextBatch(bp sdk.PluginState, evts sdk.EventWriters) (int, error) {
	i := 0
	b.ticker.Reset(time.Millisecond * 30)

	for i < evts.Len() {
		select {
		case line := <-b.t.Lines:
			// if line == nil {
			// 	// No new lines, return early
			// 	return i, sdk.ErrTimeout
			// }
			if line.Err != nil {
				return i, line.Err
			}

			// Add an event to the batch
			evt := evts.Get(i)
			if _, err := evt.Writer().Write([]byte(line.Text)); err != nil {
				return i, err
			}
			i++
		case <-b.ticker.C:
			// Timeout occurred, return early
			return i, sdk.ErrTimeout
		}
	}

	// The batch is full
	return i, nil
}

func (b *bashPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "shell.command", Display: "Shell command line", Desc: "The command line typed by user in the shell"},
	}
}

// This method is optional for source plugins, and enables the extraction
// capabilities. If the Extract method is defined, the framework expects
// an Fields method to be specified too.
func (m *bashPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	bb, err := io.ReadAll(evt.Reader())
	if err != nil {
		return err
	}

	switch req.FieldID() {
	case 0: // shell.command
		req.SetValue(string(bb))
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &bashPlugin{}
		extractor.Register(p)
		source.Register(p)
		return p
	})

}

func main() {}
