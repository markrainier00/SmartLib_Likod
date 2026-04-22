package handler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// ==========================================
// 1. SSE STREAM HANDLER
// ==========================================
func SseHandler(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")
	if schoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "School ID is required"})
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	client := &services.Client{
		SchoolID: schoolID,
		Message:  make(chan services.NotificationPayload),
	}

	services.NotifHub.Register <- client

	c.Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		defer func() {
			services.NotifHub.Unregister <- client
		}()

		fmt.Fprintf(w, ": keep-alive\n\n")
		w.Flush()

		for {
			select {
			case msg, ok := <-client.Message:
				if !ok {
					return
				}
				dataBytes, err := json.Marshal(msg)
				if err != nil {
					continue
				}

				fmt.Fprintf(w, "data: %s\n\n", string(dataBytes))
				if err := w.Flush(); err != nil {
					log.Printf("Client %s connection lost", schoolID)
					return
				}

			case <-time.After(15 * time.Second):
				fmt.Fprintf(w, ": ping\n\n")
				if err := w.Flush(); err != nil {
					return
				}
			}
		}
	}))

	return nil
}

// ==========================================
// 2. GET NOTIFICATION HISTORY
// ==========================================
func GetNotificationHistory(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	dbNotifs, err := repositories.GetNotificationsBySchoolID(schoolID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch notifications"})
	}

	var formattedNotifs []services.NotificationPayload
	for _, n := range dbNotifs {
		formattedNotifs = append(formattedNotifs, services.NotificationPayload{
			ID:   int64(n.ID),
			Msg:  n.Message,
			Time: n.CreatedAt.Format("Jan 02, 3:04 PM"),
			Read: n.IsRead,
		})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": formattedNotifs})
}

// ==========================================
// 🧹 3. CLEAR ALL NOTIFICATIONS HANDLER
// ==========================================
func ClearNotificationsHandler(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")
	if schoolID == "" {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "School ID is required"})
	}

	// 🚀 UPDATE: Tuluyan nang buburahin sa Database para hindi na bumalik pag-relogin
	if err := database.DB.Where("school_id = ?", schoolID).Delete(&model.Notification{}).Error; err != nil {
		fmt.Println("❌ Error clearing notifications:", err)
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to clear notifications"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "message": "All notifications permanently cleared"})
}

// ==========================================
// ✅ 4. MARK SINGLE NOTIFICATION AS READ
// ==========================================
func MarkNotificationAsReadHandler(c *fiber.Ctx) error {
	notifID := c.Params("id")

	// 🚀 Ise-set ang is_read = true sa database para mawala ang red highlight
	if err := database.DB.Model(&model.Notification{}).
		Where("id = ?", notifID).
		Update("is_read", true).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to mark notification as read",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Notification marked as read",
	})
}
