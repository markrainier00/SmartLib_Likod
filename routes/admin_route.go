package routes

import (
	"SmartLib_Likod/handler"
	"SmartLib_Likod/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupAdminRoutes(api fiber.Router) {
	admin := api.Group("/admin", middleware.AuthMiddleware)
	admin.Get("/registrations", handler.GetAllUsers)
	admin.Get("/studentUsers", handler.GetStudentUsers)
	admin.Put("/status", handler.UpdateUserStatus)
	admin.Delete("/:school_id", handler.DeleteUser)
}
