FROM rockylinux:9

WORKDIR /app

RUN dnf update -y && dnf install -y python3 python3-pip
RUN python3 -m venv /opt/venv

COPY requirements_lock.txt .
RUN /opt/venv/bin/pip3 install -r requirements_lock.txt

COPY . .

CMD ["/opt/venv/bin/python3", "-m", "apollo.rpmworker"]
