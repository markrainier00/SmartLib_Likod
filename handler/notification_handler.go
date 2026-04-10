package handler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gofiber/fiber/v2"
)

// 1. 📦 ANG ITSURA NG NOTIFICATION NATIN
type Notification struct {
	Type    string      `json:"type"`
	Message string      `json:"message"`
	Role    string      `json:"role"`
	Data    interface{} `json:"data"`
}

// 2. 📡 ANG BROADCASTING HUB
type NotificationHub struct {
	Clients    map[chan Notification]bool
	Broadcast  chan Notification
	Register   chan chan Notification
	Unregister chan chan Notification
	mu         sync.Mutex
}

var NotifHub = &NotificationHub{
	Clients:    make(map[chan Notification]bool),
	Broadcast:  make(chan Notification),
	Register:   make(chan chan Notification),
	Unregister: make(chan chan Notification),
}

// StartHub - Pinapatakbo ito sa background
func (h *NotificationHub) StartHub() {
	for {
		select {
		case client := <-h.Register:
			h.mu.Lock()
			h.Clients[client] = true
			h.mu.Unlock()
			fmt.Println("🟢 SSE Client Connected. Total:", len(h.Clients))

		case client := <-h.Unregister:
			h.mu.Lock()
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client)
				fmt.Println("🔴 SSE Client Disconnected. Total:", len(h.Clients))
			}
			h.mu.Unlock()

		case notif := <-h.Broadcast:
			h.mu.Lock()
			for client := range h.Clients {
				client <- notif
			}
			h.mu.Unlock()
		}
	}
}

// 3. 🚀 ANG ENDPOINT NA TATAWAGIN NG REACT (SSE)
func SSEHandler(c *fiber.Ctx) error {
	// I-setup ang headers para alam ng browser na live streaming ito
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	// Gumawa ng channel para sa bagong user na kumonekta
	clientChan := make(chan Notification)
	NotifHub.Register <- clientChan

	// Kapag umalis na sa page yung user, i-disconnect natin
	// Na-apply na ang fix dito: inalis ang 'true'
	c.Context().SetConnectionClose()

	// Dito mangyayari ang walang-katapusang pagpapadala ng data (Streaming)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		// Siguraduhing ma-unregister pag nag-close ang browser
		defer func() {
			NotifHub.Unregister <- clientChan
		}()

		for {
			select {
			case notif := <-clientChan:
				// I-convert ang struct sa JSON para mabasa ng React
				data, _ := json.Marshal(notif)

				// Format ng SSE: "data: {json_string}\n\n"
				fmt.Fprintf(w, "data: %s\n\n", string(data))

				// I-push palabas papunta sa React
				err := w.Flush()
				if err != nil {
					// Kapag nag-error (e.g. pinatay yung wifi), tigil na ang loop
					return
				}
			}
		}
	})

	return nil
}
