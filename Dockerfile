FROM python:3.11-slim

# تثبيت الأدوات
RUN apt-get update && apt-get install -y curl gnupg && rm -rf /var/lib/apt/lists/*

# تعيين مجلد العمل
WORKDIR /app

# نسخ المتطلبات وتثبيتها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# تثبيت Playwright مع التبعيات
RUN playwright install --with-deps

# نسخ الكود
COPY ./app ./app

# فتح البورت 80 داخل الحاوية
EXPOSE 80

USER root

CMD ["uvicorn", "app.apiforanalyzesite:app", "--host", "0.0.0.0", "--port", "80"]
