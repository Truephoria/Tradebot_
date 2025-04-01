import json
import os
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class Setting(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True)
    key = Column(String(50), unique=True)
    value = Column(String(255))

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def token_required(event):
    # Same as above
    pass

def validate_setting_value(key, value):
    # Same as in app.py
    pass

def lambda_handler(event, context):
    path = event["path"]
    method = event["httpMethod"]
    body = json.loads(event.get("body", "{}") or "{}")
    db_session = Session()

    try:
        if path == "/api/settings" and method == "GET":
            is_valid, error = token_required(event)
            if not is_valid:
                return error
            settings = db_session.query(Setting).all()
            settings_dict = {}
            for setting in settings:
                value = setting.value
                if setting.key in ['botEnabled', 'enableTrailingStop']:
                    value = value.lower() == 'true'
                elif setting.key in ['maxDailyLoss', 'maxTradesPerDay', 'minimumRRR', 'riskValue']:
                    value = float(value)
                settings_dict[setting.key] = value
            return {"statusCode": 200, "body": json.dumps({"status": "success", "settings": settings_dict})}

        elif path == "/api/settings" and method in ["POST", "PUT"]:
            is_valid, error = token_required(event)
            if not is_valid:
                return error
            for key, value in body.items():
                validated_value = validate_setting_value(key, value)
                setting = db_session.query(Setting).filter_by(key=key).first()
                if setting:
                    setting.value = validated_value
                else:
                    new_setting = Setting(key=key, value=validated_value)
                    db_session.add(new_setting)
            db_session.commit()
            settings = db_session.query(Setting).all()
            settings_dict = {s.key: s.value for s in settings}
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "status": "success",
                    "message": "Settings updated",
                    "settings": settings_dict
                })
            }

        else:
            return {"statusCode": 405, "body": json.dumps({"error": "Method not allowed"})}

    except Exception as e:
        db_session.rollback()
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
    finally:
        db_session.close()