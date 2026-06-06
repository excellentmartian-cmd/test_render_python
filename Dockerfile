FROM python:3.11-slim

WORKDIR /app

# 只用标准库，无需安装额外依赖
COPY app.py .

# 数据目录
RUN mkdir -p /app/data

ENV UI_HOST=0.0.0.0
ENV UI_PORT=8787
ENV DATA_DIR=/app/data

EXPOSE 8787

CMD ["python3", "app.py"]
