# Crypto Analyzer — Auth Service

## Table of Contents
- [Overview](#overview)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Database Migrations](#database-migrations)
- [Security](#security)

## Overview

Crypto Analyzer Auth Service — высокопроизводительный и безопасный сервис аутентификации и 
авторизации, реализованный на Go с использованием gRPC. Поддерживает регистрацию, логин, 
обновление токенов, верификацию access токенов и выход.

Основные возможности:
- Регистрация пользователей с валидацией данных
- Логин с генерацией JWT access и refresh токенов
- Обновление access токена и refresh токена через refresh токен
- Верификация валидности access токена и получение по нему данных
- Логаут с удалением refresh токена


## Project Structure
````
├── cmd/ # Точка входа в сервис (main)
├── gen/ # Сгенерированные файлы (grpc)
├── internal/
│ ├── app/ # Сборка и инициализация сервиса
│ ├── config/ # Конфигурация
│ ├── controller/ # GRPC контроллеры
│ ├── domain/ # Сущности и бизнес-ошибки
│ ├── infrastructure/ # Логгер, клиенты БД, редис, JWT
│ ├── service/ # Бизнес-логика
│ └──  storage/ # Реализация доступа к БД, Redis, JWT
├── logs/ # Логи
├── migrations/ # SQL миграции базы данных
├── proto/ # Protobuf описания
├── tests/ # Интеграционные тесты
├── .env
├── .gitignore
├── docker-compose.test.yml
├── docker-compose.yml
├── go.mod
├── Taskfile.yml
└── README.md
````

## Requirements

- Go 1.20+
- PostgreSQL 13+
- Redis 6+
- Protoc + gRPC plugin
- Docker (для локального запуска)


## API Reference
````
gRPC методы (AuthService):

Register	Регистрация пользователя, получение токенов
Login	Аутентификация, получение токенов
Refresh	Обновление access токена и refresh токена через refresh токен
Verify	Верификация валидности access токена и получение по нему данных
Logout	Выход и удаление refresh токена

Все методы используют контекст с trace-id и логированием.
````

## Architecture

Сервис построен по принципам DDD (Domain Driven Design) с четким разделением слоев:

Controller — gRPC API, обработка входящих запросов

Service — бизнес-логика

Domain — сущности, ошибки бизнес-логики

Storage — интерфейсы и реализации для работы с Postgres, Redis, JWT

Infrastructure — логгер, соединение с БД, redis


## Tests

Интеграционные тесты проверяют полный сценарий регистрации, логина, обновления и логаута.
Используется Allure-go для удобной генерации отчетов.


## Database Migrations

Используется golang-migrate для управления миграциями.


## Security

Использование JWT с секретным ключом и ограниченным TTL
Refresh токены хранятся в Redis с автоматическим истечением
Пароли хранятся в PostgreSQL в виде bcrypt-хешей

## Quick Start

Установить зависимостей
   `go mod tidy`

Запуск инфраструктуры
   `task up-infra`

Запуск тестовой инфраструктуры
   `task up-infra-test`

Сборка бинарника сервиса
   `task build`

Запуск сервиса локально
   `task run`

Запуск интеграционных тестов
   `task test`

Остановка инфраструктуры
   `task down-infra`

Остановка тестовой инфраструктуры
   `task down-infra-test`

Очистка скомпилированного бинарника
   `task clean`


