package services

import (
	"fmt" // <-- Idinagdag para sa ating CCTV logs
	"log"
	"time"

	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

// NotificationPayload - Format na ipapadala sa React frontend
type NotificationPayload struct {
	ID   int64  `json:"id"`
	Msg  string `json:"msg"`
	Time string `json:"time"`
	Read bool   `json:"read"`
}

// Client struct para sa bawat nag-connect na student
type Client struct {
	SchoolID string
	Message  chan NotificationPayload
}

// NotificationHub nagmamanage ng lahat ng online clients
type NotificationHub struct {
	Clients    map[string]*Client
	Register   chan *Client
	Unregister chan *Client
}

// Global Hub Instance
var NotifHub = &NotificationHub{
	Clients:    make(map[string]*Client),
	Register:   make(chan *Client),
	Unregister: make(chan *Client),
}

// StartHub - Pinapatakbo sa background (goroutine)
func (h *NotificationHub) StartHub() {
	for {
		select {
		case client := <-h.Register:
			h.Clients[client.SchoolID] = client
			log.Printf("Client connected: %s. Total online: %d\n", client.SchoolID, len(h.Clients))

		case client := <-h.Unregister:
			if _, ok := h.Clients[client.SchoolID]; ok {
				delete(h.Clients, client.SchoolID)
				close(client.Message)
				log.Printf("Client disconnected: %s. Total online: %d\n", client.SchoolID, len(h.Clients))
			}
		}
	}
}

// SendNotification - Helper para magbato ng mensahe (Indibidwal)
func (h *NotificationHub) SendNotification(schoolID string, payload NotificationPayload) {
	if client, ok := h.Clients[schoolID]; ok {
		client.Message <- payload
	}
}

// ==========================================
// 📢 ROLE-BASED BROADCASTING (MAY CCTV NA)
// ==========================================

// BroadcastToRole - Mag-send ng notification sa lahat ng users na may specific role (e.g., "Student")
func BroadcastToRole(role string, message string) {
	fmt.Println("📢 BROADCAST TRIGGERED PARA SA ROLE:", role)

	// 1. Kunin lahat ng user na may ganitong role
	users, err := repositories.GetUsersByRole(role)
	if err != nil {
		fmt.Println("🚨 ERROR SA PAGHANAP NG USERS:", err)
		return
	}

	// 👁️ CCTV: Ilan ang nahanap niya?
	fmt.Printf("👥 NAKAHANAP NG %d NA STUDENTS NA MAY 'Active' STATUS\n", len(users))

	if len(users) == 0 {
		fmt.Println("⚠️ WALANG MAPADALHAN! Baka hindi 'Active' ang status ng students sa database?")
		return
	}

	// 2. I-loop at i-send sa bawat isa
	for _, user := range users {
		// A. Save sa Database para sa history nila
		newNotif := &model.Notification{
			SchoolID: user.SchoolID,
			Message:  message,
			IsRead:   false,
		}

		// I-save ang notification
		err := repositories.CreateNotification(newNotif)
		if err != nil {
			log.Printf("Failed to save broadcast notif for %s: %v\n", user.SchoolID, err)
			continue // Ituloy pa rin sa susunod na student kahit may error ang isa
		}

		// B. I-send via SSE para tumunog nang real-time sa browser
		payload := NotificationPayload{
			ID:   int64(newNotif.ID),
			Msg:  message,
			Time: time.Now().Format("Jan 02, 3:04 PM"),
			Read: false,
		}

		fmt.Println("✅ IPINADALA ANG NOTIF KAY:", user.SchoolID)
		// I-send gamit ang Hub
		NotifHub.SendNotification(user.SchoolID, payload)
	}
}
