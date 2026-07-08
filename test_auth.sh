#!/usr/bin/env bash
# Быстрая проверка эндпоинтов регистрации/логина руками, curl-ом.
# Запуск: bash test_auth.sh  (сервер должен уже работать на localhost:8000)

set -e
BASE="http://localhost:8000"

echo "=== 1. Регистрация нового пользователя ==="
REGISTER_RESPONSE=$(curl -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"anna@example.com","password":"1234","name":"Анна"}')
echo "$REGISTER_RESPONSE"
TOKEN=$(echo "$REGISTER_RESPONSE" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "Токен: $TOKEN"
echo

echo "=== 2. Повторная регистрация тем же email (должна упасть с 400) ==="
curl -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"anna@example.com","password":"1234","name":"Анна"}'
echo
echo

echo "=== 3. Логин с правильным паролем ==="
curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"anna@example.com","password":"1234"}'
echo
echo

echo "=== 4. Логин с неправильным паролем (должен упасть с 401) ==="
curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"anna@example.com","password":"wrong"}'
echo
echo

echo "=== 5. /auth/me с валидным токеном ==="
curl -s "$BASE/auth/me" -H "Authorization: Bearer $TOKEN"
echo
echo

echo "=== 6. /auth/me без токена (должен упасть с 401) ==="
curl -s "$BASE/auth/me"
echo
