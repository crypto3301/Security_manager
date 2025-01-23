# Security Manager

## Описание задачи
Реализована программа для управления учетными записями и контроля доступа в операционной системе Windows, использующая возможности **Windows API**.

### Основные возможности:
- Получение списка пользователей и групп.
- Управление учетными записями (добавление, удаление пользователей и групп).
- Назначение и удаление привилегий.
- Управление членством пользователей в группах.

---

## Команды

| Команда      | Описание                                      |
|--------------|----------------------------------------------|
| `[get]`      | Получить список пользователей и групп.       |
| `[user]`     | Добавить пользователя.                       |
| `[group]`    | Добавить группу.                             |
| `[prv]`      | Назначить привилегии пользователю/группе.    |
| `[addprv]`   | Добавить привилегии пользователю/группе.     |
| `[removeprv]`| Удалить привилегии у пользователя/группы.    |
| `[du/dg]`    | Удалить пользователя/группу.                 |
| `[move]`     | Добавить пользователя в группу.              |
| `[remove]`   | Удалить пользователя из группы.              |

---

## Как запустить

1. Скачайте и соберите проект:
   ```bash
   git clone https://github.com/crypto3301/Security_manager.git
