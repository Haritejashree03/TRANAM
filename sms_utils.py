import requests

def send_sms(phone, message):
    SMS_API_KEY = "8iqlChnk3bS7ZvHNycTLYOfgG0DPtQIJpVWFUXum4s5Br1M2ExwtvnFzMJgVeQUqB28jW7sIbpTlxS9G"  # Fast2SMS / msg91 / 2Factor

    url = "https://www.fast2sms.com/dev/bulkV2"

    payload = {
        "route": "v3",
        "sender_id": "TXTIND",
        "message": message,
        "numbers": phone
    }

    headers = {
        "authorization": SMS_API_KEY
    }

    try:
        response = requests.post(url, data=payload, headers=headers)
        print("Fast2SMS Response:", response.text)
        return True
    except Exception as e:
        print("SMS ERROR:", e)
        return False
