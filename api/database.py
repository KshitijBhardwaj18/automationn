"""SQLite database for tracking customer deployments."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    Enum,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

from api.models import DeploymentStatus


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""

    pass


class CustomerDeploymentRecord(Base):
    """Database model for customer deployments."""

    __tablename__ = "customer_deployments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    customer_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(20), nullable=False)
    stack_name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    aws_region: Mapped[str] = mapped_column(String(20), nullable=False)
    role_arn: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[DeploymentStatus] = mapped_column(
        Enum(DeploymentStatus), nullable=False, default=DeploymentStatus.PENDING
    )
    pulumi_deployment_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    outputs: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class Database:
    """Database connection and operations."""

    def __init__(self, database_url: str = "sqlite:///./byoc_platform.db"):
        """Initialize database connection."""
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    def create_deployment(
        self,
        customer_id: str,
        environment: str,
        aws_region: str,
        role_arn: str,
    ) -> CustomerDeploymentRecord:
        """Create a new deployment record."""
        stack_name = f"{customer_id}-{environment}"

        with self.get_session() as session:
            existing = (
                session.query(CustomerDeploymentRecord).filter_by(stack_name=stack_name).first()
            )
            if existing:
                raise ValueError(f"Deployment {stack_name} already exists")

            record = CustomerDeploymentRecord(
                customer_id=customer_id,
                environment=environment,
                stack_name=stack_name,
                aws_region=aws_region,
                role_arn=role_arn,
                status=DeploymentStatus.PENDING,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def get_deployment(
        self,
        customer_id: str,
        environment: str,
    ) -> Optional[CustomerDeploymentRecord]:
        """Get deployment by customer ID and environment."""
        stack_name = f"{customer_id}-{environment}"
        with self.get_session() as session:
            return session.query(CustomerDeploymentRecord).filter_by(stack_name=stack_name).first()

    def get_deployment_by_stack(
        self,
        stack_name: str,
    ) -> Optional[CustomerDeploymentRecord]:
        """Get deployment by stack name."""
        with self.get_session() as session:
            return session.query(CustomerDeploymentRecord).filter_by(stack_name=stack_name).first()

    def update_deployment_status(
        self,
        stack_name: str,
        status: DeploymentStatus,
        pulumi_deployment_id: Optional[str] = None,
        outputs: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Optional[CustomerDeploymentRecord]:
        """Update deployment status."""
        with self.get_session() as session:
            record = (
                session.query(CustomerDeploymentRecord).filter_by(stack_name=stack_name).first()
            )
            if not record:
                return None

            record.status = status
            record.updated_at = datetime.utcnow()

            if pulumi_deployment_id:
                record.pulumi_deployment_id = pulumi_deployment_id
            if outputs:
                record.outputs = outputs
            if error_message:
                record.error_message = error_message

            session.commit()
            session.refresh(record)
            return record

    def get_deployments_by_customer(
        self,
        customer_id: str,
    ) -> list[CustomerDeploymentRecord]:
        """Get all deployments for a customer."""
        with self.get_session() as session:
            return list(
                session.query(CustomerDeploymentRecord).filter_by(customer_id=customer_id).all()
            )


db = Database()
