Tutorial:

Instalação de VENV:\
python -m venv .venv\
source .venv/bin/activate\
pip install pip-tools

Instalação de requirements:\
pip-sync requirements/requirements.txt requirements/requirements-dev.txt\
OU\
Executar [install_requirements_dev.sh](scripts%2Finstall_requirements_dev.sh)

Execução do programa:\
Executar [run.py](bin%2Frun.py) com working directory na raiz do projeto ($totpy_auth/ python3.12 bin/run.py)