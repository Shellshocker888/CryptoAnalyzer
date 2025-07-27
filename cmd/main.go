package main

import (
	"context"
	pb "crypto_analyzer_auth_service/gen/go"
	"crypto_analyzer_auth_service/internal/config"
	"crypto_analyzer_auth_service/internal/handler"
	"crypto_analyzer_auth_service/internal/service"
	"crypto_analyzer_auth_service/internal/storage"
	"database/sql"
	"fmt"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"net/http"
	"os"
	"time"
)

func initPostgres(cfg *config.PostgresConfig) (*sql.DB, error) {

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SslMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(1 * time.Hour)

	return db, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := config.LoadConfig()
	if err != nil {
		fmt.Printf("failed to load config: %v", err)
		os.Exit(1)
	}

	cfgPostgres, err := config.LoadPostgresConfig()
	if err != nil {
		fmt.Printf("failed to load postgres config: %v", err)
		os.Exit(1)
	}

	DB, err := initPostgres(cfgPostgres)
	if err != nil {
		fmt.Printf("failed to init postgres DB: %v", err)
		os.Exit(1)
	}
	defer DB.Close()

	cfgRedis, err := config.LoadRedisConfig()
	if err != nil {
		fmt.Printf("failed to load redis config: %v", err)
		os.Exit(1)
	}

	redisClient, err := storage.InitRedisClient(ctx, cfgRedis)
	if err != nil {
		fmt.Printf("failed to init redis client: %v", err)
		os.Exit(1)
	}

	cfgJWT, err := config.LoadJWTConfig()
	if err != nil {
		fmt.Printf("failed to load JWT config: %v", err)
		os.Exit(1)
	}

	userStorage, err := storage.NewUserStorage(DB)
	if err != nil {
		fmt.Printf("failed to init user storage: %v", err)
		os.Exit(1)
	}

	userSessionManager := storage.NewSessionManager(cfgRedis, redisClient)
	userJWTManager := storage.NewJWTManager(cfgJWT)

	authService := service.NewService(userStorage, userSessionManager, userJWTManager)
	authHandler := handler.NewAuthHandler(authService)

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, authHandler)

	listener50051, err := net.Listen("tcp", ":50051")
	if err != nil {
		fmt.Printf("failed to init listener for port 50051: %v", err)
		os.Exit(1)
	}

	go func() {
		err = grpcServer.Serve(listener50051)
		if err != nil {
			fmt.Printf("failed to start grpc server with listener: %v", err)
			os.Exit(1)
		}
	}()

	go func() {
		mux := runtime.NewServeMux()

		opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		err = pb.RegisterAuthServiceHandlerFromEndpoint(context.Background(), mux, "localhost:50051", opts)
		if err != nil {
			fmt.Printf("failed to register grpc gateway: %w", err)
			os.Exit(1)
		}

		err = http.ListenAndServe(":8080", mux)
		if err != nil {
			fmt.Printf("failed to start http server: %w", err)
			os.Exit(1)
		}
	}()

	select {}
}
