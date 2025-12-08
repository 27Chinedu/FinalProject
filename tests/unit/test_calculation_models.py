# tests/unit/test_calculation_models.py

import pytest
from uuid import uuid4
from app.models.calculation import Calculation, Addition, Subtraction, Multiplication, Division

def test_calculation_create_addition():
    """Test creating addition calculation"""
    user_id = uuid4()
    calc = Calculation.create("addition", user_id, [1, 2, 3])
    assert isinstance(calc, Addition)
    assert calc.user_id == user_id
    assert calc.inputs == [1, 2, 3]

def test_calculation_create_subtraction():
    """Test creating subtraction calculation"""
    user_id = uuid4()
    calc = Calculation.create("subtraction", user_id, [10, 3])
    assert isinstance(calc, Subtraction)
    assert calc.type == "subtraction"

def test_calculation_create_multiplication():
    """Test creating multiplication calculation"""
    user_id = uuid4()
    calc = Calculation.create("multiplication", user_id, [2, 3])
    assert isinstance(calc, Multiplication)
    assert calc.type == "multiplication"

def test_calculation_create_division():
    """Test creating division calculation"""
    user_id = uuid4()
    calc = Calculation.create("division", user_id, [10, 2])
    assert isinstance(calc, Division)
    assert calc.type == "division"

def test_calculation_create_unsupported_type():
    """Test creating calculation with unsupported type"""
    user_id = uuid4()
    with pytest.raises(ValueError, match="Unsupported calculation type"):
        Calculation.create("modulo", user_id, [10, 3])

def test_calculation_create_case_insensitive():
    """Test creating calculation with uppercase type"""
    user_id = uuid4()
    calc = Calculation.create("ADDITION", user_id, [1, 2])
    assert isinstance(calc, Addition)

def test_addition_get_result():
    """Test addition result calculation"""
    user_id = uuid4()
    calc = Calculation.create("addition", user_id, [5, 10, 15])
    result = calc.get_result()
    assert result == 30

def test_subtraction_get_result():
    """Test subtraction result calculation"""
    user_id = uuid4()
    calc = Calculation.create("subtraction", user_id, [100, 30, 20])
    result = calc.get_result()
    assert result == 50

def test_multiplication_get_result():
    """Test multiplication result calculation"""
    user_id = uuid4()
    calc = Calculation.create("multiplication", user_id, [2, 3, 4])
    result = calc.get_result()
    assert result == 24

def test_division_get_result():
    """Test division result calculation"""
    user_id = uuid4()
    calc = Calculation.create("division", user_id, [100, 2, 5])
    result = calc.get_result()
    assert result == 10

def test_addition_not_list():
    """Test addition with non-list input"""
    user_id = uuid4()
    calc = Calculation.create("addition", user_id, [1, 2])
    calc.inputs = "not a list"
    with pytest.raises(ValueError, match="Inputs must be a list"):
        calc.get_result()

def test_addition_insufficient_inputs():
    """Test addition with less than 2 inputs"""
    user_id = uuid4()
    calc = Calculation.create("addition", user_id, [1, 2])
    calc.inputs = [1]
    with pytest.raises(ValueError, match="at least two numbers"):
        calc.get_result()

def test_subtraction_not_list():
    """Test subtraction with non-list input"""
    user_id = uuid4()
    calc = Calculation.create("subtraction", user_id, [1, 2])
    calc.inputs = "not a list"
    with pytest.raises(ValueError, match="Inputs must be a list"):
        calc.get_result()

def test_subtraction_insufficient_inputs():
    """Test subtraction with insufficient inputs"""
    user_id = uuid4()
    calc = Calculation.create("subtraction", user_id, [1, 2])
    calc.inputs = [1]
    with pytest.raises(ValueError, match="at least two numbers"):
        calc.get_result()

def test_multiplication_not_list():
    """Test multiplication with non-list input"""
    user_id = uuid4()
    calc = Calculation.create("multiplication", user_id, [1, 2])
    calc.inputs = "not a list"
    with pytest.raises(ValueError, match="Inputs must be a list"):
        calc.get_result()

def test_multiplication_insufficient_inputs():
    """Test multiplication with insufficient inputs"""
    user_id = uuid4()
    calc = Calculation.create("multiplication", user_id, [1, 2])
    calc.inputs = [1]
    with pytest.raises(ValueError, match="at least two numbers"):
        calc.get_result()

def test_division_not_list():
    """Test division with non-list input"""
    user_id = uuid4()
    calc = Calculation.create("division", user_id, [1, 2])
    calc.inputs = "not a list"
    with pytest.raises(ValueError, match="Inputs must be a list"):
        calc.get_result()

def test_division_insufficient_inputs():
    """Test division with insufficient inputs"""
    user_id = uuid4()
    calc = Calculation.create("division", user_id, [1, 2])
    calc.inputs = [1]
    with pytest.raises(ValueError, match="at least two numbers"):
        calc.get_result()

def test_division_by_zero():
    """Test division by zero raises error"""
    user_id = uuid4()
    calc = Calculation.create("division", user_id, [100, 0])
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        calc.get_result()

def test_division_by_zero_in_sequence():
    """Test division by zero in middle of sequence"""
    user_id = uuid4()
    calc = Calculation.create("division", user_id, [100, 2, 0, 5])
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        calc.get_result()

def test_calculation_repr():
    """Test calculation string representation"""
    user_id = uuid4()
    calc = Calculation.create("addition", user_id, [1, 2, 3])
    repr_str = repr(calc)
    assert "Calculation" in repr_str
    assert "addition" in repr_str
    assert "[1, 2, 3]" in repr_str