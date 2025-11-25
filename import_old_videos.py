import os
from app import app, db
from models import Video
from datetime import datetime

VIDEO_ROOT = "static/videos"

def import_old_videos():
    with app.app_context():

        if not os.path.exists(VIDEO_ROOT):
            print(f"❌ Folder not found: {VIDEO_ROOT}")
            return

        print("\n📁 Scanning for user folders...")

        for folder in os.listdir(VIDEO_ROOT):
            folder_path = os.path.join(VIDEO_ROOT, folder)

            # Ensure it's a folder and matches pattern: user_<id>
            if not os.path.isdir(folder_path) or not folder.startswith("user_"):
                continue

            try:
                user_id = int(folder.replace("user_", ""))
            except:
                print(f"⚠️ Skipping invalid folder: {folder}")
                continue

            print(f"\n➡️ Importing videos for user_id = {user_id}")

            # Scan all video files inside this user folder
            for filename in os.listdir(folder_path):
                if not filename.lower().endswith(('.mp4', '.avi', '.mov', '.webm', '.ogg')):
                    continue

                db_filename = f"user_{user_id}/{filename}"

                # Check if already exists in DB
                exists = Video.query.filter_by(user_id=user_id, filename=db_filename).first()
                if exists:
                    print(f"   ⚠️ Skipped (already in DB): {db_filename}")
                    continue

                # Create new DB record
                video = Video(
                    user_id=user_id,
                    filename=db_filename,
                    name=filename,
                    created_at=datetime.utcnow()
                )

                db.session.add(video)
                print(f"   ✅ Added: {db_filename}")

        db.session.commit()
        print("\n🎉 IMPORT COMPLETE! All user videos added to DB.\n")

if __name__ == "__main__":
    import_old_videos()
