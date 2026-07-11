#!/usr/bin/env bash
# Проверка эндпоинтов контактов. Требует, чтобы test_auth.sh/сервер уже
# зарегистрировал пользователя anna@example.com (пароль 1234) —
# либо просто перерегистрирует заново, если сервер только что перезапущен.
# Запуск: bash test_contacts.sh (сервер должен работать на localhost:8000)

set -e
BASE="http://localhost:8000"

echo "=== 0. Логин (или регистрация, если сервер свежий) ==="
LOGIN_RESPONSE=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"anna@example.com","password":"1234"}')

if echo "$LOGIN_RESPONSE" | grep -q "token"; then
  TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
else
  echo "Логин не удался, регистрирую заново..."
  REGISTER_RESPONSE=$(curl -s -X POST "$BASE/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"anna@example.com","password":"1234","name":"Анна"}')
  TOKEN=$(echo "$REGISTER_RESPONSE" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
fi
echo "Токен: $TOKEN"
echo

echo "=== 1. Регистрирую второго пользователя (для проверки is_mimir_user) ==="
curl -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"igor@example.com","password":"1234","name":"Игорь"}' > /dev/null
echo "Готово"
echo

echo "=== 2. Синхронизация контактов (один — пользователь Мимира, один — нет) ==="
curl -s -X POST "$BASE/contacts/sync" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "contacts": [
      {"name": "Игорь Соин", "phone": "+79990000001", "email": "igor@example.com"},
      {"name": "Мама", "phone": "+79990000002", "email": null}
    ]
  }'
echo
echo

echo "=== 3. Список контактов ==="
curl -s "$BASE/contacts" -H "Authorization: Bearer $TOKEN"
echo
echo

echo "=== 4. Синхронизация без токена (должна упасть с 401) ==="
curl -s -X POST "$BASE/contacts/sync" \
  -H "Content-Type: application/json" \
  -d '{"contacts": []}'
echo
echo

echo "=== 5. Удаление несуществующего контакта (должно упасть с 404) ==="
curl -s -X DELETE "$BASE/contacts/doesnotexist" -H "Authorization: Bearer $TOKEN"
echo
