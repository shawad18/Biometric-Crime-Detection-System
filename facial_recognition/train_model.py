import face_recognition
import os
import pickle

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE, 'uploads', 'face_images')
ENCODINGS_FILE = os.path.join(os.path.dirname(__file__), 'encodings.pkl')

def train_model():
    """Alias for encode_faces for backward compatibility"""
    return encode_faces()

def encode_faces():
    known_encodings = []
    known_names = []

    for filename in os.listdir(DATA_DIR):
        if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
            path = os.path.join(DATA_DIR, filename)
            image = face_recognition.load_image_file(path)
            encodings = face_recognition.face_encodings(image)

            if encodings:
                known_encodings.append(encodings[0])
                known_names.append(os.path.splitext(filename)[0])

    data = {"encodings": known_encodings, "names": known_names}
    with open(ENCODINGS_FILE, "wb") as f:
        pickle.dump(data, f)
    print("[INFO] Encodings saved to", ENCODINGS_FILE)

if __name__ == '__main__':
    encode_faces()
