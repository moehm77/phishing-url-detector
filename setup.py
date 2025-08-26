from setuptools import setup, find_packages

setup(
    name='phishing-url-detector',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'streamlit==1.28.0',
        'pandas==2.2.2',
        'numpy==1.26.4',
        'scikit-learn==1.3.2',
        'joblib==1.3.2',
        'seaborn==0.13.0',
        'matplotlib==3.8.1'
    ]
)