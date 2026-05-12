package handler

import (
	"bufio"
	"fmt"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

var (
	sseClients   = make(map[chan string]struct{})
	sseClientsMu sync.Mutex
)

func NotifyNewMessage(senderRole string) {
	sseClientsMu.Lock()
	defer sseClientsMu.Unlock()
	payload := fmt.Sprintf(`{"type":"new_message","sender_role":"%s"}`, senderRole)
	for ch := range sseClients {
		select {
		case ch <- payload:
		default:
		}
	}
}

func SSEHandler(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	ch := make(chan string, 8)

	sseClientsMu.Lock()
	sseClients[ch] = struct{}{}
	sseClientsMu.Unlock()

	notify := c.Context().Done()

	c.Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		defer func() {
			sseClientsMu.Lock()
			delete(sseClients, ch)
			sseClientsMu.Unlock()
			close(ch)
		}()

		for {
			select {
			case msg := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", msg)
				if err := w.Flush(); err != nil {
					return
				}
			case <-notify:
				return
			}
		}
	}))

	return nil
}
