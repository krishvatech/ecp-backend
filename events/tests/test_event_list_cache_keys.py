from django.http import QueryDict
from django.test import SimpleTestCase

from events.cache_utils import event_list_cache_key


class EventListCacheKeyTests(SimpleTestCase):
    class AdminUser:
        id = 123
        is_authenticated = True
        is_superuser = True
        is_staff = True

    def test_archived_tab_has_a_distinct_cache_key(self):
        user = self.AdminUser()

        all_params = QueryDict("limit=6&offset=0")
        archived_params = QueryDict("limit=6&offset=0&is_archived=true")
        hidden_params = QueryDict("limit=6&offset=0&is_hidden=true")

        all_key = event_list_cache_key(user, all_params)
        archived_key = event_list_cache_key(user, archived_params)
        hidden_key = event_list_cache_key(user, hidden_params)

        self.assertNotEqual(all_key, archived_key)
        self.assertNotEqual(hidden_key, archived_key)
        self.assertNotEqual(all_key, hidden_key)

    def test_archived_filter_value_changes_the_cache_key(self):
        user = self.AdminUser()

        enabled_key = event_list_cache_key(
            user, QueryDict("is_archived=true&limit=6&offset=0")
        )
        disabled_key = event_list_cache_key(
            user, QueryDict("is_archived=false&limit=6&offset=0")
        )

        self.assertNotEqual(enabled_key, disabled_key)
