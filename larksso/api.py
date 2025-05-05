import frappe
import requests
from urllib.parse import urlencode

def get_lark_credentials():
    social_login_key = frappe.get_doc("Social Login Key", {"provider_name": "Lark"})

    if not social_login_key:
        frappe.throw("Lark Social Login Key not found. Please configure it in Social Login Keys.")

    app_id = social_login_key.client_id
    app_secret = social_login_key.get_password("client_secret")

    if not app_id or not app_secret:
        frappe.throw("Lark Client ID or Client Secret not configured in Social Login Keys.")

    return app_id, app_secret

@frappe.whitelist(allow_guest=True)
def oauth2_login(state: str):
    """
    Callback for processing code and state for user added providers
    """

    code = frappe.form_dict.get("code")

    if not code:
        error_log_name = frappe.log_error("Lark OAuth Callback Error: Code not found (E.g. from declined Lark Authorization)", "Lark OAuth Callback Error")
        redirect_page = "/login"

        params = urlencode({"login_error_code": "Lark authorization failed!", "error_id": error_log_name})

        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = f"{redirect_page}?{params}"
        return

    headers = {
        "Content-Type": "application/json",
    }

    app_id, app_secret = get_lark_credentials()
    body = {
        "app_id": app_id,
        "app_secret": app_secret,
    }

    cache = frappe.cache()
    cached_app_tok = cache.get_value("app_access_token")

    if cached_app_tok:
        app_access_token = cached_app_tok
        frappe.log(f"Using cached app access token: {app_access_token}")
        # print("Using cached app access token:", app_access_token)
    else:
        response = requests.post("https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal", headers=headers, json=body)
        response = response.json()
        app_access_token = response.get("app_access_token")

        cache.set_value("app_access_token", app_access_token, expires_in_sec=6000)

    headers = {
        "Authorization": f"Bearer {app_access_token}",
        "Content-Type": "application/json"
    }

    body = {
        "grant_type": "authorization_code",
        "code": code,
    }

    response = requests.post("https://open.larksuite.com/open-apis/authen/v1/oidc/access_token", headers=headers, json=body)
    response = response.json()

    frappe.log(f"User Token Response: {response}")
    # print("User Token Response: ", response)

    user_access_token = response.get("data").get("access_token")
    headers = {
        "Authorization": f"Bearer {user_access_token}",
        "Content-Type": "application/json"
    }

    response = requests.get("https://open.larksuite.com/open-apis/authen/v1/user_info", headers=headers)
    response = response.json()

    email = response.get("data").get("email")
    user_row = frappe.get_list("User",
        filters={"email": email, "enabled": 1},
        fields=["name"],
        limit_page_length=1,
        ignore_permissions=True,
    )

    error_log_name = frappe.log_error(f"Email {email} not found!", "Lark OAuth Callback Error")
    redirect_page = "/login"

    params = urlencode({"login_error_code": f"Email {email} not found", "error_id": error_log_name})

    if not user_row:
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = f"{redirect_page}?{params}"
        return

    email = user_row[0].name

    login_manager = frappe.auth.LoginManager()
    login_manager.user = email
    login_manager.post_login()

    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = "/helpdesk"