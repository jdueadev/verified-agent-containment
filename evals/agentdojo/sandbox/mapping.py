"""Which AgentDojo tool calls leave the user's machine, and for whom.

This is the one table a reviewer reads to check the adapter. Each tool of a
suite maps to LOCAL or to an Outward rule:

- LOCAL: the call only reads or changes the user's own state (their inbox,
  drive, calendar, bank settings, the simulated catalogue a tool reads from).
  It never reaches the gate.
- Outward(writes, destinations): the call's effect reaches a party other than
  the user. `destinations(args, env)` names those parties as "<kind>:<party>"
  strings; each distinct one becomes one gate request with its own origin.
  An empty list means this particular call reaches nobody (an event without
  participants).

A tool missing from its suite's table is an error, never a pass.
"""

from dataclasses import dataclass
from typing import Any, Callable

# Email destinations are the recipient's domain (the mail server that takes the
# message). "address" would make every recipient its own destination.
EMAIL_DESTINATION = "domain"


@dataclass(frozen=True)
class Outward:
    writes: bool
    # (validated arguments, environment) -> [(destination, party detail)]
    destinations: Callable[[dict[str, Any], Any], list[tuple[str, str]]]


LOCAL = None


def _emails(addresses, owner=None):
    found = []
    for address in addresses or []:
        if owner and address.lower() == owner.lower():
            continue  # mail to oneself reaches no other party
        domain = address.rsplit("@", 1)[-1].lower()
        found.append((f"email:{domain if EMAIL_DESTINATION == 'domain' else address.lower()}", address))
    return found


def _owner(env):
    return env.inbox.account_email


def _event_participants(env, event_id):
    event = env.calendar.events.get(str(event_id))
    return event.participants if event else []


def _web(url):
    for scheme in ("https://", "http://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
    host = url.split("/", 1)[0].split("?", 1)[0].lower()
    return [(f"web:{host}", url)]


def _scheduled_recipient(env, args):
    if args.get("recipient"):
        return args["recipient"]
    found = next((t for t in env.bank_account.scheduled_transactions if t.id == args["id"]), None)
    return found.recipient if found else None


def _iban(iban):
    return [(f"iban:{iban}", iban)] if iban else []


SEND_EMAIL = Outward(True, lambda a, env: _emails([*a["recipients"], *(a.get("cc") or []), *(a.get("bcc") or [])], _owner(env)))
# Invitations go to the participants (create_calendar_event sends them an email).
CREATE_EVENT = Outward(True, lambda a, env: _emails(a.get("participants"), _owner(env)))
# Cancelling or moving an event emails everyone already invited.
NOTIFY_PARTICIPANTS = Outward(True, lambda a, env: _emails(_event_participants(env, a["event_id"]), _owner(env)))

TABLE: dict[str, dict[str, Outward | None]] = {
    "workspace": {
        "send_email": SEND_EMAIL,
        "delete_email": LOCAL,
        "get_unread_emails": LOCAL,
        "get_sent_emails": LOCAL,
        "get_received_emails": LOCAL,
        "get_draft_emails": LOCAL,
        "search_emails": LOCAL,
        "search_contacts_by_name": LOCAL,
        "search_contacts_by_email": LOCAL,
        "get_current_day": LOCAL,
        "search_calendar_events": LOCAL,
        "get_day_calendar_events": LOCAL,
        "create_calendar_event": CREATE_EVENT,
        "cancel_calendar_event": NOTIFY_PARTICIPANTS,
        "reschedule_calendar_event": NOTIFY_PARTICIPANTS,
        # The tool's description says the new participants are emailed; its code
        # only adds them. Either way they now see the event.
        "add_calendar_event_participants": Outward(True, lambda a, env: _emails(a["participants"], _owner(env))),
        "append_to_file": LOCAL,
        "search_files_by_filename": LOCAL,
        "create_file": LOCAL,
        "delete_file": LOCAL,
        "get_file_by_id": LOCAL,
        "list_files": LOCAL,
        "share_file": Outward(True, lambda a, env: _emails([a["email"]], _owner(env))),
        "search_files": LOCAL,
    },
    "travel": {
        "get_user_information": LOCAL,
        # The hotel, restaurant, car and flight lookups read the simulated
        # catalogue the suite ships; they are treated like a local database.
        "get_all_hotels_in_city": LOCAL,
        "get_hotels_prices": LOCAL,
        "get_rating_reviews_for_hotels": LOCAL,
        "get_hotels_address": LOCAL,
        "get_all_restaurants_in_city": LOCAL,
        "get_cuisine_type_for_restaurants": LOCAL,
        "get_restaurants_address": LOCAL,
        "get_rating_reviews_for_restaurants": LOCAL,
        "get_dietary_restrictions_for_all_restaurants": LOCAL,
        "get_contact_information_for_restaurants": LOCAL,
        "get_price_for_restaurants": LOCAL,
        "check_restaurant_opening_hours": LOCAL,
        "get_all_car_rental_companies_in_city": LOCAL,
        "get_car_types_available": LOCAL,
        "get_rating_reviews_for_car_rental": LOCAL,
        "get_car_fuel_options": LOCAL,
        "get_car_rental_address": LOCAL,
        "get_car_price_per_day": LOCAL,
        "create_calendar_event": CREATE_EVENT,
        "search_calendar_events": LOCAL,
        "get_day_calendar_events": LOCAL,
        "cancel_calendar_event": NOTIFY_PARTICIPANTS,
        # A booking sends the user's details to the business.
        "reserve_hotel": Outward(True, lambda a, env: [(f"hotel:{a['hotel']}", a["hotel"])]),
        "reserve_car_rental": Outward(True, lambda a, env: [(f"car-rental:{a['company']}", a["company"])]),
        "reserve_restaurant": Outward(True, lambda a, env: [(f"restaurant:{a['restaurant']}", a["restaurant"])]),
        "get_flight_information": LOCAL,
        "send_email": SEND_EMAIL,
    },
    "banking": {
        "get_iban": LOCAL,
        "send_money": Outward(True, lambda a, env: _iban(a["recipient"])),
        # Scheduled and changed payments reach their recipient later.
        "schedule_transaction": Outward(True, lambda a, env: _iban(a["recipient"])),
        "update_scheduled_transaction": Outward(True, lambda a, env: _iban(_scheduled_recipient(env, a))),
        "get_balance": LOCAL,
        "get_most_recent_transactions": LOCAL,
        "get_scheduled_transactions": LOCAL,
        "read_file": LOCAL,
        "get_user_info": LOCAL,
        # The user's own account settings: no other party receives anything.
        "update_password": LOCAL,
        "update_user_info": LOCAL,
    },
    "slack": {
        "get_channels": LOCAL,
        # The added user can now read the channel.
        "add_user_to_channel": Outward(True, lambda a, env: [(f"slack-user:{a['user']}", a["user"])]),
        "read_channel_messages": LOCAL,
        "read_inbox": LOCAL,
        "send_direct_message": Outward(True, lambda a, env: [(f"slack-user:{a['recipient']}", a["recipient"])]),
        "send_channel_message": Outward(True, lambda a, env: [(f"slack-channel:{a['channel']}", a["channel"])]),
        "get_users_in_channel": LOCAL,
        # The invitation is an email to user_email.
        "invite_user_to_slack": Outward(True, lambda a, env: _emails([a["user_email"]])),
        "remove_user_from_slack": Outward(True, lambda a, env: [(f"slack-user:{a['user']}", a["user"])]),
        "get_webpage": Outward(False, lambda a, env: _web(a["url"])),
        "post_webpage": Outward(True, lambda a, env: _web(a["url"])),
    },
}


class UnmappedTool(Exception):
    """A tool the table does not cover. The case fails instead of guessing."""


def rule(suite: str, tool: str) -> Outward | None:
    try:
        return TABLE[suite][tool]
    except KeyError:
        raise UnmappedTool(f"{suite}.{tool} is not in evals/agentdojo/sandbox/mapping.py") from None


def requests(suite: str, tool: str, args: dict[str, Any], env) -> tuple[bool, list[tuple[str, list[str]]]]:
    """(writes, [(destination, [party details])]) for one call, one entry per distinct destination."""
    found = rule(suite, tool)
    if found is LOCAL:
        return False, []
    grouped: dict[str, list[str]] = {}
    for destination, detail in found.destinations(args, env):
        grouped.setdefault(destination, []).append(detail)
    return found.writes, sorted(grouped.items())
