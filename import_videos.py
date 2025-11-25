import os
import sqlite3
import datetime

DB_PATH = "women_safety.db"
BASE_FOLDER = "static/uploads/videos"

# Allowed video formats
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mov", ".mkv", ".webm"}

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("🔍 Scanning video folders...")

# Loop through each user folder
if os.path.exists(BASE_FOLDER):
    for user_id in os.listdir(BASE_FOLDER):

        user_path = os.path.join(BASE_FOLDER, user_id)

        if not os.path.isdir(user_path):
            continue

        # Ensure folder is numeric (user_id)
        if not user_id.isdigit():
            print(f"❌ Skipping non-user folder: {user_path}")
            continue

        uid = int(user_id)

        # Scan each file inside the folder
        for file in os.listdir(user_path):
            file_path = os.path.join(user_path, file)

            # Check if valid video
            ext = os.path.splitext(file)[1].lower()
            if ext not in VIDEO_EXTENSIONS:
                continue

            # Avoid duplicate filenames for the same user
            cursor.execute(
                "SELECT id FROM video WHERE user_id = ? AND filename = ?",
                (uid, file)
            )
            exists = cursor.fetchone()

            if exists:
                print(f"⚠️ Already exists in DB: User {uid} → {file}")
                continue

            # Insert into database
            cursor.execute(
                """
                INSERT INTO video (user_id, name, filename, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    uid,
                    os.path.splitext(file)[0],  # name = file name without extension
                    file,
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            )

            print(f"✅ Imported: User {uid} → {file}")

else:
    print("❌ Base video folder does not exist!")

conn.commit()
conn.close()

print("\n🎉 Import Complete!")
