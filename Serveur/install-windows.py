import os
import subprocess
import sys

def create_virtualenv(venv_dir):
    """Crée un environnement virtuel s'il n'existe pas déjà."""
    if not os.path.exists(venv_dir):
        print(f"Création de l'environnement virtuel dans {venv_dir}...")
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    else:
        print(f"L'environnement virtuel existe déjà dans {venv_dir}.")

def install_packages(venv_dir, packages):
    """Installe les paquets nécessaires dans l'environnement virtuel."""
    pip_executable = os.path.join(venv_dir, "Scripts", "pip.exe")
    
    if not os.path.exists(pip_executable):
        print(f"pip introuvable dans {pip_executable}. Assurez-vous que l'environnement virtuel a été créé correctement.")
        sys.exit(1)
    
    try:
        print("Mise à jour de pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        print("Installation des paquets...")
        subprocess.check_call([pip_executable, "install"] + packages)
        print("Paquets installés avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'installation des paquets : {e}")
        sys.exit(1)

def main():
    venv_dir = "venv"
    packages = [
        "flask==2.3.2",
        "flask-sqlalchemy==3.0.5",
        "werkzeug==2.3.7"
    ]
    create_virtualenv(venv_dir)
    install_packages(venv_dir, packages)
    print(f"Tout est prêt ! Activez l'environnement avec : {venv_dir}\\Scripts\\activate")

if __name__ == "__main__":
    main()
