package handler

import (
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func GetStudentConversation(c *fiber.Ctx) error {
	studentID := c.Params("student_id")
	var convo model.Conversation

	result := database.DB.Preload("Messages", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Where("student_id = ?", studentID).First(&convo)

	if result.Error != nil {
		convo = model.Conversation{
			StudentID: studentID,
		}
		database.DB.Create(&convo)
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": convo})
}

func GetAllConversations(c *fiber.Ctx) error {
	var convos []model.Conversation

	if err := database.DB.Preload("Messages", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Order("updated_at desc").Find(&convos).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch conversations"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": convos})
}

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

	if body.ConversationID == 0 {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Missing Conversation ID. Make sure frontend sends the correct ID."})
	}

	msg := model.Message{
		ConversationID: body.ConversationID,
		SenderID:       body.SenderID,
		SenderRole:     body.SenderRole,
		Content:        body.Content,
	}

	if err := database.DB.Create(&msg).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to send message"})
	}
	NotifyNewMessage(body.SenderRole)
	database.DB.Model(&model.Conversation{}).Where("id = ?", body.ConversationID).Update("updated_at", time.Now())

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Message sent", "data": msg})
}

func MarkMessagesAsRead(c *fiber.Ctx) error {
	type Req struct {
		ConversationID uint   `json:"conversation_id"`
		ViewerRole     string `json:"viewer_role"`
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	roleToMark := "student"
	if body.ViewerRole == "student" || body.ViewerRole == "Student" {
		roleToMark = "admin"
	}

	database.DB.Model(&model.Message{}).
		Where("conversation_id = ? AND sender_role = ? AND is_read = ?", body.ConversationID, roleToMark, false).
		Update("is_read", true)

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Messages marked as read"})
}
