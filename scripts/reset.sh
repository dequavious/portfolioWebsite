sudo -u postgres psql --command="DROP DATABASE IF EXISTS portfolio;"
sudo -u postgres psql --command="CREATE DATABASE portfolio OWNER webadmin;"

cd ..

rm -rf static/media/images/*
rm -rf static/media/documents/*
rm -rf staticfiles
rm -rf portfolio/migrations

python3 manage.py makemigrations portfolio
python3 manage.py migrate
python3 manage.py createsuperuser
python3 manage.py collectstatic