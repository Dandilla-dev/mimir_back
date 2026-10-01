"""
api/routes/contacts.py — контакты пользователя (телефонная книга клиента).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import contacts_store, get_current_user
from api.schemas import ContactsListResponse, ContactsSyncRequest, contact_to_out
from core.auth_store import User
from core.contacts_store import ContactsError

router = APIRouter()


@router.post("/contacts/sync", response_model=ContactsListResponse)
def sync_contacts(
    req: ContactsSyncRequest, current_user: User = Depends(get_current_user)
):
    """Принимает список контактов из телефонной книги клиента, полностью
    заменяет ими контакты текущего пользователя и отмечает, кто из них
    уже зарегистрирован в Мимире (по email)."""
    raw = [c.model_dump() for c in req.contacts]
    contacts = contacts_store.sync_contacts(current_user.user_id, raw)
    return ContactsListResponse(contacts=[contact_to_out(c) for c in contacts])


@router.get("/contacts", response_model=ContactsListResponse)
def list_contacts(current_user: User = Depends(get_current_user)):
    contacts = contacts_store.list_contacts(current_user.user_id)
    return ContactsListResponse(contacts=[contact_to_out(c) for c in contacts])


@router.delete("/contacts/{contact_id}")
def delete_contact(contact_id: str, current_user: User = Depends(get_current_user)):
    try:
        contacts_store.remove_contact(current_user.user_id, contact_id)
    except ContactsError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "deleted", "contact_id": contact_id}