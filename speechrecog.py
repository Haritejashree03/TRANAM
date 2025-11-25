import cv2
import time
import speech_recognition as sr
import random
import serial
import requests

# -----------------------------
# Serial Port Configuration
# -----------------------------
ser = serial.Serial(
    port='COM6',
    baudrate=115200,
    timeout=1
)

print("Serial connection established. Waiting for data...")


# -----------------------------
# Send video info to Flask API
# -----------------------------
def save_video_to_flask(user_id, filename):
    try:
        res = requests.post(
            "http://127.0.0.1:5000/api/save-video",
            json={"user_id": user_id, "filename": filename, "name": filename}
        )
        print("📡 Flask API Response:", res.text)
    except Exception as e:
        print("❌ ERROR sending video to Flask:", e)


# -----------------------------
# Record Video
# -----------------------------
def record_video(filename=None, duration=10):

    if filename is None:
        filename = "static/videos/alert_video_" + str(random.randint(1, 9999)) + ".avi"

    # Initialize ESP Camera
    cap = cv2.VideoCapture('http://10.113.180.216:81/stream')

    if not cap.isOpened():
        print("❌ Error: ESP32 Camera not accessible")
        return

    frame_width = int(cap.get(3))
    frame_height = int(cap.get(4))

    out = cv2.VideoWriter(filename, cv2.VideoWriter_fourcc(*'XVID'), 20.0,
                          (frame_width, frame_height))

    print(f"🎥 Recording video for {duration} seconds...")
    start_time = time.time()

    while int(time.time() - start_time) < duration:
        ret, frame = cap.read()
        if ret:
            out.write(frame)
            cv2.imshow('Recording...', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        else:
            print("⚠ Error: Failed to read frame")
            break

    cap.release()
    out.release()
    cv2.destroyAllWindows()

    print(f"✅ Video saved as {filename}")

    # -----------------------------------------
    # SEND VIDEO TO FLASK DATABASE
    # -----------------------------------------
    db_filename = filename.replace("static/videos/", "")  # remove path

    USER_ID = 1  # ← Set the correct logged-in user ID here
    save_video_to_flask(USER_ID, db_filename)


# -----------------------------
# Speech Recognition Loop
# -----------------------------
def listen_for_keywords():
    recognizer = sr.Recognizer()
    mic = sr.Microphone()

    print("🎙 Listening for 'help' or 'danger'...")

    with mic as source:
        recognizer.adjust_for_ambient_noise(source)

    while True:
        try:
            with mic as source:
                print("Listening...")
                audio = recognizer.listen(source, timeout=None, phrase_time_limit=5)

            try:
                text = recognizer.recognize_google(audio).lower()
                print(f"Detected speech: {text}")

                if "help" in text or "danger" in text:
                    print("🚨 Keyword detected! Recording video...")
                    record_video()

                    ser.write(str.encode("help\n\r"))
                    time.sleep(1)

            except sr.UnknownValueError:
                print("Could not understand audio.")
            except sr.RequestError:
                print("Speech Recognition service unavailable.")

        except KeyboardInterrupt:
            print("\n🛑 Exiting...")
            break


# -----------------------------
# MAIN ENTRY
# -----------------------------
if __name__ == "__main__":
    listen_for_keywords()