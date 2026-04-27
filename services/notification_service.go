package services

import (
	"fmt"
	"log"
	"time"

	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

type NotificationPayload struct {
	ID   int64  `json:"id"`
	Msg  string `json:"msg"`
	Time string `json:"time"`
	Read bool   `json:"read"`
}

type Client struct {
	SchoolID string
	Message  chan NotificationPayload
}

type NotificationHub struct {
	Clients    map[string]*Client
	Register   chan *Client
	Unregister chan *Client
}

var NotifHub = &NotificationHub{
	Clients:    make(map[string]*Client),
	Register:   make(chan *Client),
	Unregister: make(chan *Client),
}

func NotifyWishlistUsers(ISBN string, title string) {
	schoolIDs, err := repositories.GetWishlistNotifyUsersByBook(ISBN)
	if err != nil {
		log.Printf("NotifyWishlistUsers: failed to fetch wishlist users: %v\n", err)
		return
	}

	if len(schoolIDs) == 0 {
		fmt.Println("NotifyWishlistUsers: no wishlist users to notify")
		return
	}

	message := fmt.Sprintf("Good news! \"%s\" is now available for borrowing.", title)

	for _, schoolID := range schoolIDs {
		newNotif := &model.Notification{
			SchoolID: schoolID,
			Message:  message,
			IsRead:   false,
		}

		err := repositories.CreateNotification(newNotif)
		if err != nil {
			log.Printf("NotifyWishlistUsers: failed to save notif for %s: %v\n", schoolID, err)
			continue
		}

		payload := NotificationPayload{
			ID:   int64(newNotif.ID),
			Msg:  message,
			Time: time.Now().Format("Jan 02, 3:04 PM"),
			Read: false,
		}

		fmt.Println("NotifyWishlistUsers: sent notification to:", schoolID)
		NotifHub.SendNotification(schoolID, payload)
	}
}

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

func (h *NotificationHub) SendNotification(schoolID string, payload NotificationPayload) {
	if client, ok := h.Clients[schoolID]; ok {
		client.Message <- payload
	}
}

func BroadcastToRole(role string, message string) {
	users, err := repositories.GetUsersByRole(role)
	if err != nil {
		fmt.Println("Error looking for users:", err)
		return
	}

	fmt.Printf("Found %d students with 'Active' status\n", len(users))

	if len(users) == 0 {
		fmt.Println("No users found")
		return
	}

	for _, user := range users {
		newNotif := &model.Notification{
			SchoolID: user.SchoolID,
			Message:  message,
			IsRead:   false,
		}

		err := repositories.CreateNotification(newNotif)
		if err != nil {
			log.Printf("Failed to save broadcast notif for %s: %v\n", user.SchoolID, err)
			continue
		}

		payload := NotificationPayload{
			ID:   int64(newNotif.ID),
			Msg:  message,
			Time: time.Now().Format("Jan 02, 3:04 PM"),
			Read: false,
		}

		fmt.Println("Sent notificationt to:", user.SchoolID)
		NotifHub.SendNotification(user.SchoolID, payload)
	}
}
