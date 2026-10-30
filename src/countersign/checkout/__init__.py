"""Protocol-neutral checkout session storage and lifecycle, shared by the UCP and ACP adapters.

Both adapters keep their sessions as the same canonical checkout in the same table, so a cart is the
same bytes whichever protocol made it. Nothing here knows a protocol or a web framework.
"""
