package handler

import (
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"

	// "SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
)

func BorrowBook(c *fiber.Ctx) error {
	var input services.BorrowInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid input format", "isSuccess": false})
	}

	if err := services.BorrowBookService(input); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": err.Error(), "isSuccess": false})
	}

	return c.Status(201).JSON(fiber.Map{"message": "Request sent to Staff!", "isSuccess": true})
}

func GetAllRequests(c *fiber.Ctx) error {
	requests, err := services.GetAllRequestsService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch requests",
			IsSuccess: false,
			Error:     err,
		})
	}
	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Requests fetched successfully",
		Data:    requests,
	})
}

func GetDashboardStats(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data": fiber.Map{
			"pendingRegistrations": repositories.GetPendingRegCount(),
			"borrowRequests":       repositories.GetPendingBorrowCount(),
			"activeBorrows":        repositories.GetActiveBorrowCount(),
		},
	})
}

func ReleaseBook(c *fiber.Ctx) error {
	type Req struct {
		SchoolID string `json:"school_id"`
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid request", "isSuccess": false})
	}
	if err := services.ReleaseBookService(body.SchoolID); err != nil {
		return c.Status(500).JSON(fiber.Map{"message": err.Error(), "isSuccess": false})
	}
	return c.JSON(fiber.Map{"message": "Book released!", "isSuccess": true})
}

func RejectBook(c *fiber.Ctx) error {
	type Req struct {
		SchoolID string `json:"school_id"`
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid request", "isSuccess": false})
	}

	err := repositories.UpdateTransactionStatus(body.SchoolID, "Pending", "Rejected")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"message": "Failed to reject request", "isSuccess": false})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Request rejected successfully"})
}
