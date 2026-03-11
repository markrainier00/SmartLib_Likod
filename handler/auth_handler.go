package handler

import (
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
)

func Register(c *fiber.Ctx) error {
	var input services.RegisterInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.FirstName == "" || input.LastName == "" || input.Email == "" || input.SchoolID == "" || input.Program == "" || input.Year == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if len(input.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Password must be at least 8 characters",
			IsSuccess: false,
			Error:     nil,
		})
	}

	user, err := services.RegisterUser(input)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "201",
		Message: "Registration successful",
		Data:    user,
	})
}

func Signin(c *fiber.Ctx) error {
	var input services.SigninInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Identifier == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	user, err := services.SigninUser(input)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Sign in successfull",
		Data:    user,
	})
}

func ForgotPassword(c *fiber.Ctx) error {
	var input services.ForgotPasswordInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Identifier == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	services.ForgotPasswordService(input)

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "If an account exists for this email, you’ll receive a password reset link shortly.",
		Data:    nil,
	})
}

func ResetPassword(c *fiber.Ctx) error {
	var input services.ResetPasswordInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Token == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ResetPasswordService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Password reset successfully",
		Data:    nil,
	})
}
