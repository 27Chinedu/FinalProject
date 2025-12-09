# tests/integration/test_performance.py

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from uuid import uuid4
from app.models.user import User
from app.models.calculation import Calculation


class TestConcurrency:
    """Test concurrent operations and race conditions"""

    def test_concurrent_user_registration(self, db_session):
        """Test multiple users registering concurrently"""
        from sqlalchemy.orm import sessionmaker
        from app.database import engine

        SessionMaker = sessionmaker(bind=engine)

        def register_user(index):
            """Register a user in a separate session"""
            session = SessionMaker()
            try:
                user_data = {
                    "first_name": f"User{index}",
                    "last_name": f"Concurrent{index}",
                    "email": f"concurrent{index}_{uuid4()}@example.com",
                    "username": f"concurrent_{index}_{uuid4()}",
                    "password": "TestPass123!"
                }
                user = User.register(session, user_data)
                session.commit()
                return user.id
            except Exception as e:
                session.rollback()
                raise e
            finally:
                session.close()

        # Register 10 users concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(register_user, i) for i in range(10)]
            results = [future.result() for future in as_completed(futures)]

        # All registrations should succeed
        assert len(results) == 10
        assert len(set(results)) == 10  # All unique IDs

    def test_concurrent_calculation_creation(self, db_session, fake_user_data):
        """Test concurrent calculation creation for same user"""
        from sqlalchemy.orm import sessionmaker
        from app.database import engine

        # Create user first
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()
        user_id = user.id

        SessionMaker = sessionmaker(bind=engine)

        def create_calculation(index):
            """Create a calculation in a separate session"""
            session = SessionMaker()
            try:
                calc = Calculation.create("addition", user_id, [index, index + 1])
                calc.result = calc.get_result()
                session.add(calc)
                session.commit()
                calc_id = calc.id
                session.close()
                return calc_id
            except Exception as e:
                session.rollback()
                session.close()
                raise e

        # Create 20 calculations concurrently
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(create_calculation, i) for i in range(20)]
            results = [future.result() for future in as_completed(futures)]

        # All should succeed
        assert len(results) == 20

        # Verify all calculations exist
        calcs = db_session.query(Calculation).filter(
            Calculation.user_id == user_id
        ).all()
        assert len(calcs) == 20

    def test_concurrent_profile_updates(self, db_session, fake_user_data):
        """Test concurrent profile updates - race condition test"""
        from sqlalchemy.orm import sessionmaker
        from app.database import engine

        # Create user
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()
        user_id = user.id

        SessionMaker = sessionmaker(bind=engine)

        def update_profile(index):
            """Update user profile in separate session"""
            session = SessionMaker()
            try:
                user = session.query(User).filter(User.id == user_id).first()
                user.first_name = f"Updated{index}"
                session.commit()
                session.close()
                return True
            except Exception as e:
                session.rollback()
                session.close()
                raise e

        # Update profile 10 times concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(update_profile, i) for i in range(10)]
            results = [future.result() for future in as_completed(futures)]

        # All updates should complete
        assert len(results) == 10

        # Final state should have one of the updates
        db_session.expire_all()
        final_user = db_session.query(User).filter(User.id == user_id).first()
        assert final_user.first_name.startswith("Updated")

    def test_concurrent_calculation_deletion(self, db_session, fake_user_data):
        """Test concurrent deletion of calculations"""
        from sqlalchemy.orm import sessionmaker
        from app.database import engine

        # Create user and calculations
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc_ids = []
        for i in range(10):
            calc = Calculation.create("addition", user.id, [i, i + 1])
            calc.result = calc.get_result()
            db_session.add(calc)
            db_session.commit()
            db_session.refresh(calc)
            calc_ids.append(calc.id)

        SessionMaker = sessionmaker(bind=engine)

        def delete_calculation(calc_id):
            """Delete calculation in separate session"""
            session = SessionMaker()
            try:
                calc = session.query(Calculation).filter(
                    Calculation.id == calc_id
                ).first()
                if calc:
                    session.delete(calc)
                    session.commit()
                    session.close()
                    return True
                session.close()
                return False
            except Exception:
                session.rollback()
                session.close()
                return False

        # Delete all concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(delete_calculation, cid) for cid in calc_ids]
            results = [future.result() for future in as_completed(futures)]

        # Verify all deleted
        remaining = db_session.query(Calculation).filter(
            Calculation.user_id == user.id
        ).count()
        assert remaining == 0


class TestPerformance:
    """Test performance with large datasets"""

    def test_large_input_calculation(self, db_session, fake_user_data):
        """Test calculation with very large input array"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Create calculation with 1000 inputs
        large_inputs = list(range(1, 1001))

        start_time = time.time()
        calc = Calculation.create("addition", user.id, large_inputs)
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()
        elapsed = time.time() - start_time

        # Should complete in reasonable time (< 1 second)
        assert elapsed < 1.0
        assert calc.result == sum(large_inputs)

    def test_bulk_calculation_creation(self, db_session, fake_user_data):
        """Test creating many calculations"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        start_time = time.time()

        # Create 100 calculations
        for i in range(100):
            calc = Calculation.create("addition", user.id, [i, i + 1])
            calc.result = calc.get_result()
            db_session.add(calc)

        db_session.commit()
        elapsed = time.time() - start_time

        # Should complete in reasonable time (< 5 seconds)
        assert elapsed < 5.0

        # Verify all created
        count = db_session.query(Calculation).filter(
            Calculation.user_id == user.id
        ).count()
        assert count == 100

    def test_list_many_calculations(self, db_session, fake_user_data):
        """Test listing user with many calculations"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Create 500 calculations
        for i in range(500):
            calc = Calculation.create("addition", user.id, [i, i + 1])
            calc.result = calc.get_result()
            db_session.add(calc)
        db_session.commit()

        # Query should be fast
        start_time = time.time()
        calcs = db_session.query(Calculation).filter(
            Calculation.user_id == user.id
        ).all()
        elapsed = time.time() - start_time

        assert len(calcs) == 500
        assert elapsed < 1.0  # Should complete in < 1 second

    def test_user_with_many_calculations_profile_load(self, db_session, fake_user_data):
        """Test profile loading for user with many calculations"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Create 1000 calculations
        for i in range(1000):
            calc = Calculation.create("addition", user.id, [i, i + 1])
            calc.result = calc.get_result()
            db_session.add(calc)
            if i % 100 == 0:
                db_session.commit()
        db_session.commit()

        # Load profile with calculation count
        start_time = time.time()
        user = db_session.query(User).filter(User.id == user.id).first()
        calc_count = len(user.calculations)
        elapsed = time.time() - start_time

        assert calc_count == 1000
        assert elapsed < 2.0  # Should load in < 2 seconds

    def test_multiplication_large_numbers(self, db_session, fake_user_data):
        """Test multiplication with large numbers"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Large but safe numbers
        large_inputs = [100, 200, 300]

        calc = Calculation.create("multiplication", user.id, large_inputs)
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()

        assert calc.result == 100 * 200 * 300

    def test_division_precision(self, db_session, fake_user_data):
        """Test division with decimal precision"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("division", user.id, [10, 3])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()

        # Should handle floating point
        assert abs(calc.result - 3.333333) < 0.001


class TestDatabasePerformance:
    """Test database connection and transaction performance"""

    def test_sequential_commits(self, db_session, fake_user_data):
        """Test performance of sequential commits"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        start_time = time.time()

        # 50 sequential commits
        for i in range(50):
            calc = Calculation.create("addition", user.id, [i, i + 1])
            calc.result = calc.get_result()
            db_session.add(calc)
            db_session.commit()

        elapsed = time.time() - start_time

        # Should complete reasonably fast
        assert elapsed < 3.0

    def test_batch_commit_performance(self, db_session, fake_user_data):
        """Test performance of batch commits"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        start_time = time.time()

        # Add 100 items, commit once
        for i in range(100):
            calc = Calculation.create("addition", user.id, [i, i + 1])
            calc.result = calc.get_result()
            db_session.add(calc)

        db_session.commit()
        elapsed = time.time() - start_time

        # Batch should be faster than sequential
        assert elapsed < 2.0

    def test_query_filtering_performance(self, db_session, fake_user_data):
        """Test query filtering with many records"""
        # Create 5 users
        users = []
        for i in range(5):
            user_data = {
                "first_name": f"User{i}",
                "last_name": f"Test{i}",
                "email": f"user{i}_{uuid4()}@example.com",
                "username": f"user{i}_{uuid4()}",
                "password": "TestPass123!"
            }
            user = User.register(db_session, user_data)
            users.append(user)
        db_session.commit()

        # Create 100 calculations for each user
        for user in users:
            for i in range(100):
                calc = Calculation.create("addition", user.id, [i, i + 1])
                calc.result = calc.get_result()
                db_session.add(calc)
        db_session.commit()

        # Query specific user's calculations
        start_time = time.time()
        target_user = users[2]
        calcs = db_session.query(Calculation).filter(
            Calculation.user_id == target_user.id
        ).all()
        elapsed = time.time() - start_time

        assert len(calcs) == 100
        assert elapsed < 0.5  # Should be very fast with proper indexing
