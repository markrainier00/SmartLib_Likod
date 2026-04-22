package handler

import (
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
)

func RegisterStaffHandler(c *fiber.Ctx) error {
	var input services.RegisterStaffInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.FirstName == "" || input.LastName == "" || input.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.RegisterStaffService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "201",
		Message: "Staff registration successful.",
		Data:    nil,
	})
}

func GetRegistrationHistoryHandler(c *fiber.Ctx) error {
	history, err := services.GetRegistrationHistoryService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   status.RetCode500,
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Registration history retrieved",
		Data:    history,
	})
}

func GetWholeUsers(c *fiber.Ctx) error {
	users, err := services.GetWholeUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetAllUsers(c *fiber.Ctx) error {
	users, err := services.GetAllUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetPendingUsers(c *fiber.Ctx) error {
	users, err := services.GetPendingUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func ApproveUser(c *fiber.Ctx) error {
	var input services.ApproveRejectInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ApproveUserService(input.SchoolID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User approved successfully",
		Data:    nil,
	})
}

func RejectUser(c *fiber.Ctx) error {
	var input services.ApproveRejectInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if input.Reason == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Rejection reason is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.RejectUserService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User rejected successfully",
		Data:    nil,
	})
}

func GetStudentUsers(c *fiber.Ctx) error {
	users, err := services.GetStudentUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetSpecificUser(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	users, err := services.GetSpecificUserService(schoolID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func UpdateUserStatus(c *fiber.Ctx) error {
	var input services.UpdateUserStatusInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" || input.Status == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID and status are required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.UpdateUserStatusService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User status updated successfully",
		Data:    nil,
	})
}

func ApproveInformationRequestHandler(c *fiber.Ctx) error {
	var input struct {
		ID uint `json:"id"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if input.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "ID is required",
		})
	}

	if err := services.ApproveInformationRequest(input.ID); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Request approved successfully",
	})
}

func RejectInformationRequestHandler(c *fiber.Ctx) error {
	var input struct {
		ID           uint   `json:"id"`
		RejectReason string `json:"reject_reason"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if input.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "ID is required",
		})
	}

	if input.RejectReason == "" {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Reject reason is required",
		})
	}

	if err := services.RejectInformationRequest(input.ID, input.RejectReason); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Request rejected successfully",
	})
}

func GetAllAccounts(c *fiber.Ctx) error {
	users, err := services.GetAllAccountsService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetInformationChange(c *fiber.Ctx) error {
	users, err := services.GetInformationChangeService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}
