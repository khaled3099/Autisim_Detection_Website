import tensorflow as tf
loaded_model = tf.keras.models.load_model('Model__.h5')
from tensorflow.keras.preprocessing import image
import numpy as np
import os
# Directory containing the images
directory = 'C:/Users/Famille/Desktop/Dataset/valid/Autistic'  # Replace with the path to your directory

# Get a list of all image files in the directory
img_paths = [os.path.join(directory, filename) for filename in os.listdir(directory) if filename.endswith(('.jpg', '.jpeg', '.png'))]

# Load and preprocess the images
img_arrays = []
for img_path in img_paths:
    img = image.load_img(img_path, target_size=(224, 224))  # Resize the image if necessary
    img_array = image.img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension
    img_arrays.append(img_array)

# Stack the image arrays along the batch axis
input_data = np.vstack(img_arrays)

# Normalize the images
input_data = input_data / 255.0  # Normalize pixel values to [0, 1]

# Make predictions
predictions = loaded_model.predict(input_data)

rounded_predictions = np.round(predictions)
for i in rounded_predictions:
    if i>0.5:
        print('Non Autistic')
    else:
        print('Autistic')