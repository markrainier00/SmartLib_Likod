package routes

import (
	"SmartLib_Likod/handler"
	"SmartLib_Likod/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupAuthRoutes(api fiber.Router) {
	auth := api.Group("/auth")
	auth.Post("/send-otp", handler.SendOTP)
	auth.Post("/verify-otp", handler.VerifyOTP)
	auth.Post("/check-school-id", handler.CheckSchoolID)
	auth.Get("/schools", handler.GetSchools)
	auth.Post("/register", handler.RegisterHandler)
	auth.Post("/signin", handler.Signin)
	auth.Post("/forgot-password", handler.ForgotPassword)
	auth.Post("/reset-password", handler.ResetPassword)
	auth.Post("/change-password", middleware.AuthMiddleware, handler.ChangePassword)
	auth.Post("/change-information", middleware.AuthMiddleware, handler.ChangeInformationHandler)
}
