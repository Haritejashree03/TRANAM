import os
import subprocess
from app import db, Video, app   # Make sure this matches your project structure

# Path to video folder
VIDEO_FOLDER = os.path.join("static", "videos")

def convert_avi_to_mp4():
    print("🔍 Scanning for AVI files in:", VIDEO_FOLDER)

    converted_count = 0

    with app.app_context():

        for filename in os.listdir(VIDEO_FOLDER):

            if filename.lower().endswith(".avi"):
                avi_path = os.path.join(VIDEO_FOLDER, filename)

                mp4_name = filename.replace(".avi", ".mp4")
                mp4_path = os.path.join(VIDEO_FOLDER, mp4_name)

                print(f"🎬 Converting: {filename} → {mp4_name}")

                # FFmpeg command
                command = [
                    "ffmpeg",
                    "-i", avi_path,
                    "-vcodec", "libx264",
                    "-acodec", "aac",
                    "-preset", "fast",
                    "-crf", "23",
                    mp4_path
                ]

                try:
                    subprocess.run(command, check=True)
                    os.remove(avi_path)   # delete old AVI
                    print(f"✅ Converted & removed old file: {filename}")

                    # Update in DB if exists
                    video_record = Video.query.filter_by(filename=filename).first()
                    if video_record:
                        video_record.filename = mp4_name
                        db.session.commit()
                        print("📌 Database updated:", mp4_name)

                    converted_count += 1

                except Exception as e:
                    print(f"❌ Conversion failed for {filename}: {e}")

    print(f"🎉 Task complete — {converted_count} video(s) converted.")


if __name__ == "__main__":
    convert_avi_to_mp4()
