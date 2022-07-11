package main

import (
	"enigmacamp.com/golang-sample-jwt/config"
	"enigmacamp.com/golang-sample-jwt/delivery/middleware"
	"enigmacamp.com/golang-sample-jwt/model"
	"enigmacamp.com/golang-sample-jwt/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	routerEngine := gin.Default()
	//routerEngine.Use(AuthTokenMiddleware()) // global middleware
	cfg := config.NewConfig()
	tokenService := utils.NewTokenService(cfg.TokenConfig)
	routerGroup := routerEngine.Group("/api")
	routerGroup.POST("/auth/login", func(c *gin.Context) {
		var user model.Credential
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "can't bind struct",
			})
			return
		}
		if user.Username == "enigma" && user.Password == "123" {
			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			err = tokenService.StoreAccessToken(user.Username, token)
			if err != nil {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	protectedGroup := routerGroup.Group("/master", middleware.NewTokenValidator(tokenService).RequireToken())
	protectedGroup.GET("/customer", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": ctx.GetString("user-id"),
		})
	})
	protectedGroup.GET("/product", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": ctx.GetString("user-id"),
		})
	})

	err := routerEngine.Run(":8888")
	if err != nil {
		panic(err)
	}
}
