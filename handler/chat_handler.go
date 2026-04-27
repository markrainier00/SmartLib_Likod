package handler

import (
	"fmt"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	// "SmartLib_Likod/services" // Naka-comment muna kung sakaling wala ka pang services package para sa notif

	"github.com/gofiber/fiber/v2"
)

// ==========================================
// 1. Kukunin o Gagawa ng Conversation para sa Student
// ==========================================
func GetStudentConversation(c *fiber.Ctx) error {
	studentID := c.Params("student_id")
	var convo model.Conversation

	result := database.DB.Preload("Messages").Where("student_id = ?", studentID).First(&convo)

	if result.Error != nil {
		convo = model.Conversation{
			StudentID: studentID,
		}
		database.DB.Create(&convo)
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": convo})
}

// ==========================================
// 2. Kukunin lahat ng Conversations para sa Admin Dashboard
// ==========================================
func GetAllConversations(c *fiber.Ctx) error {
	var convos []model.Conversation

	if err := database.DB.Preload("Messages").Order("updated_at desc").Find(&convos).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch conversations"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": convos})
}

// ==========================================
// 3. Magpapadala ng Message (Pwede galing Admin o Student)
// ==========================================
func SendMessage(c *fiber.Ctx) error {
	type Req struct {
		ConversationID uint   `json:"conversation_id"`
		SenderID       string `json:"sender_id"`
		SenderRole     string `json:"sender_role"`
		Content        string `json:"content"`
	}

	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	// 🚀 FIX: I-BLOCK AGAD KAPAG ZERO (0) ANG ID PARA HINDI MAG-CRASH ANG DATABASE!
	if body.ConversationID == 0 {
		fmt.Println("❌ BLOCK: Naka-receive ng Conversation ID na '0' galing sa React.")
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Missing Conversation ID. Make sure frontend sends the correct ID."})
	}

	msg := model.Message{
		ConversationID: body.ConversationID,
		SenderID:       body.SenderID,
		SenderRole:     body.SenderRole,
		Content:        body.Content,
	}

	// 🚀 NILAGYAN NATIN NG ERROR LOG PARA MAKITA SA TERMINAL KUNG SA DB ANG PROBLEMA
	if err := database.DB.Create(&msg).Error; err != nil {
		fmt.Println("❌ DATABASE ERROR (Create Message):", err)
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to send message"})
	}

	database.DB.Model(&model.Conversation{}).Where("id = ?", body.ConversationID).Update("updated_at", time.Now())

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Message sent", "data": msg})
}

// ==========================================
// 🚀 4. BAGONG FUNCTION: Taga-marka ng "Seen"
// ==========================================
func MarkMessagesAsRead(c *fiber.Ctx) error {
	type Req struct {
		ConversationID uint   `json:"conversation_id"`
		ViewerRole     string `json:"viewer_role"` // "admin" o "student"
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	// Kapag Admin ang nagbabasa, i-mark as read ang messages ng Student, at vice versa.
	roleToMark := "student"
	if body.ViewerRole == "student" || body.ViewerRole == "Student" {
		roleToMark = "admin"
	}

	// I-update sa database na "true" na ang is_read
	database.DB.Model(&model.Message{}).
		Where("conversation_id = ? AND sender_role = ? AND is_read = ?", body.ConversationID, roleToMark, false).
		Update("is_read", true)

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Messages marked as read"})
}
