package handler

import (
	"fmt"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
)

// Kunin lahat ng Concerns
func GetConcerns(c *fiber.Ctx) error {
	var concerns []model.Concern
	if err := database.DB.Order("created_at desc").Find(&concerns).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch concerns"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "data": concerns})
}

// Mag-reply at mag-resolve ng Concern
func UpdateConcern(c *fiber.Ctx) error {
	id := c.Params("id")
	type Req struct {
		Reply  string `json:"reply"`
		Status string `json:"status"`
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	var concern model.Concern
	if err := database.DB.First(&concern, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"isSuccess": false, "message": "Concern not found"})
	}

	if body.Reply != "" {
		concern.Reply = body.Reply
		concern.Status = "In Review"
	}
	if body.Status != "" {
		concern.Status = body.Status
	}

	database.DB.Save(&concern)

	// ==========================================
	// 🔔 TRIGGER: Notif sa Student kapag sumagot si Admin
	// Pinalitan natin ang concern.SchoolID ng concern.Student
	// ==========================================
	msg := "💬 An Admin has replied to or updated your submitted concern. Check your support page."
	sendStudentNotification(concern.Student, msg)

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Concern updated successfully"})
}

// ==========================================
// 🚀 BAGONG DAGDAG: Gagawa ng bagong Concern galing sa Student Portal
// ==========================================
func CreateConcern(c *fiber.Ctx) error {
	var concern model.Concern

	// Kunin ang idinagdag ng student sa frontend form
	if err := c.BodyParser(&concern); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	// I-save sa Supabase database
	if err := database.DB.Create(&concern).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to save concern"})
	}

	// ==========================================
	// 🔔 TRIGGER: Notif kay Admin na may bagong ticket/concern
	// Pinalitan natin ang concern.SchoolID ng concern.Student
	// ==========================================
	adminMsg := fmt.Sprintf("📩 New Concern: Student %s submitted an inquiry. Please check the dashboard.", concern.Student)
	services.BroadcastToRole("Admin", adminMsg)
	services.BroadcastToRole("Staff", adminMsg)

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Concern submitted successfully!"})
}
