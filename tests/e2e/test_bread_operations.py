# tests/e2e/test_bread_operations.py

import pytest
from uuid import uuid4
from playwright.sync_api import Page, expect

def register_and_login_ui(page: Page, base_url: str, user_data: dict):
    """Helper function to register and login via UI"""
    # Register
    page.goto(f"{base_url}/register")
    page.fill('input[name="username"]', user_data["username"])
    page.fill('input[name="email"]', user_data["email"])
    page.fill('input[name="first_name"]', user_data["first_name"])
    page.fill('input[name="last_name"]', user_data["last_name"])
    page.fill('input[name="password"]', user_data["password"])
    page.fill('input[name="confirm_password"]', user_data["password"])
    page.click('button[type="submit"]')
    
    # Wait for redirect to login
    page.wait_for_url(f"{base_url}/login", timeout=5000)
    
    # Login
    page.fill('input[name="username"]', user_data["username"])
    page.fill('input[name="password"]', user_data["password"])
    page.click('button[type="submit"]')
    
    # Wait for dashboard
    page.wait_for_url(f"{base_url}/dashboard", timeout=5000)

# ==============================================================================
# POSITIVE TESTS - BREAD Operations
# ==============================================================================

def test_create_calculation_positive(page: Page, fastapi_server: str):
    """Test creating a calculation successfully (C in BREAD)"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"createuser_{uuid4()}",
        "email": f"create{uuid4()}@example.com",
        "first_name": "Create",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Fill in calculation form
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '10, 20, 30')
    
    # Submit form
    page.click('button[type="submit"]')
    
    # Wait for success message
    expect(page.locator('#successAlert')).to_be_visible(timeout=5000)
    expect(page.locator('#successMessage')).to_contain_text('successfully')
    
    # Verify calculation appears in table
    expect(page.locator('table tbody tr')).to_have_count(1)
    expect(page.locator('table tbody tr:first-child')).to_contain_text('addition')
    expect(page.locator('table tbody tr:first-child')).to_contain_text('10, 20, 30')
    expect(page.locator('table tbody tr:first-child')).to_contain_text('60')

def test_browse_calculations_positive(page: Page, fastapi_server: str):
    """Test browsing/listing calculations (B in BREAD)"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"browseuser_{uuid4()}",
        "email": f"browse{uuid4()}@example.com",
        "first_name": "Browse",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Create multiple calculations
    calculations = [
        ('addition', '5, 10', '15'),
        ('subtraction', '100, 25', '75'),
        ('multiplication', '3, 4, 5', '60'),
        ('division', '100, 5', '20')
    ]
    
    for calc_type, inputs, expected_result in calculations:
        page.select_option('select[name="type"]', calc_type)
        page.fill('input[name="inputs"]', inputs)
        page.click('button[type="submit"]')
        page.wait_for_timeout(500)
    
    # Verify all calculations are listed
    expect(page.locator('table tbody tr')).to_have_count(4)
    
    # Verify each calculation is displayed correctly
    for calc_type, inputs, result in calculations:
        row = page.locator(f'table tbody tr:has-text("{calc_type}")')
        expect(row).to_be_visible()
        expect(row).to_contain_text(result)

def test_read_calculation_positive(page: Page, fastapi_server: str):
    """Test reading/viewing a single calculation (R in BREAD)"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"readuser_{uuid4()}",
        "email": f"read{uuid4()}@example.com",
        "first_name": "Read",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Create a calculation
    page.select_option('select[name="type"]', 'multiplication')
    page.fill('input[name="inputs"]', '7, 8, 9')
    page.click('button[type="submit"]')
    page.wait_for_timeout(500)
    
    # Click View button - use specific selector for the button in the table row
    # The table has buttons with class "view-calc" that contain text "View"
    page.locator('table tbody tr').first.locator('.view-calc').click()
    
    # Verify modal appears with correct data
    expect(page.locator('#calculationModal')).to_be_visible()
    expect(page.locator('#modalType')).to_contain_text('multiplication')
    expect(page.locator('#modalCurrentInputs')).to_contain_text('7, 8, 9')
    expect(page.locator('#modalResult')).to_contain_text('504')
    
    # Close modal
    page.click('#closeModalBtn')
    expect(page.locator('#calculationModal')).to_be_hidden()

def test_update_calculation_positive(page: Page, fastapi_server: str):
    """Test updating a calculation (E/U in BREAD)"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"updateuser_{uuid4()}",
        "email": f"update{uuid4()}@example.com",
        "first_name": "Update",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Create a calculation
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '1, 2, 3')
    page.click('button[type="submit"]')
    page.wait_for_timeout(500)
    
    # Open view modal - use specific selector for the View button in the table
    page.locator('table tbody tr').first.locator('.view-calc').click()
    expect(page.locator('#calculationModal')).to_be_visible()
    
    # Click Edit button
    page.click('#editBtn')
    expect(page.locator('#editSection')).to_be_visible()
    
    # Update inputs
    page.fill('#modalInputs', '10, 20, 30')
    
    # Save
    page.click('#saveBtn')
    
    # Wait for success message
    expect(page.locator('#successAlert')).to_be_visible(timeout=5000)
    expect(page.locator('#successMessage')).to_contain_text('updated')
    
    # Verify updated calculation in table
    expect(page.locator('table tbody tr:first-child')).to_contain_text('10, 20, 30')
    expect(page.locator('table tbody tr:first-child')).to_contain_text('60')

def test_delete_calculation_positive(page: Page, fastapi_server: str):
    """Test deleting a calculation (D in BREAD)"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"deleteuser_{uuid4()}",
        "email": f"delete{uuid4()}@example.com",
        "first_name": "Delete",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Create two calculations
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '1, 2')
    page.click('button[type="submit"]')
    page.wait_for_timeout(500)
    
    page.select_option('select[name="type"]', 'subtraction')
    page.fill('input[name="inputs"]', '10, 5')
    page.click('button[type="submit"]')
    page.wait_for_timeout(500)
    
    # Verify 2 calculations exist
    expect(page.locator('table tbody tr')).to_have_count(2)
    
    # Delete first calculation - use specific selector for Delete button
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator('table tbody tr').first.locator('.delete-calc').click()
    
    # Wait for success message
    expect(page.locator('#successAlert')).to_be_visible(timeout=5000)
    
    # Verify only 1 calculation remains
    expect(page.locator('table tbody tr')).to_have_count(1)

# ==============================================================================
# NEGATIVE TESTS - Input Validation
# ==============================================================================

def test_create_calculation_empty_type_negative(page: Page, fastapi_server: str):
    """Test creating calculation with empty type fails"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"emptytype_{uuid4()}",
        "email": f"emptytype{uuid4()}@example.com",
        "first_name": "Empty",
        "last_name": "Type",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Try to submit without selecting type
    page.fill('input[name="inputs"]', '1, 2, 3')
    page.click('button[type="submit"]')
    
    # Wait for error alert to appear (client-side validation shows this)
    page.wait_for_timeout(500)
    
    # Check that error alert becomes visible OR the form shows an error
    # The JavaScript showError function removes the 'hidden' class
    error_alert = page.locator('#errorAlert')
    
    # Wait for the error alert to not have the hidden class
    expect(error_alert).not_to_have_class('hidden', timeout=5000)
    
    # Verify error message content
    error_text = page.locator('#errorMessage').text_content()
    assert 'type' in error_text.lower() or 'select' in error_text.lower() or 'operation' in error_text.lower()

def test_create_calculation_empty_inputs_negative(page: Page, fastapi_server: str):
    """Test creating calculation with empty inputs fails"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"emptyinputs_{uuid4()}",
        "email": f"emptyinputs{uuid4()}@example.com",
        "first_name": "Empty",
        "last_name": "Inputs",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Select type but leave inputs empty
    page.select_option('select[name="type"]', 'addition')
    page.click('button[type="submit"]')
    
    # Wait for validation
    page.wait_for_timeout(500)
    
    # Check error alert is visible (not hidden)
    error_alert = page.locator('#errorAlert')
    expect(error_alert).not_to_have_class('hidden', timeout=5000)
    
    error_text = page.locator('#errorMessage').text_content()
    assert 'empty' in error_text.lower() or 'required' in error_text.lower() or 'at least' in error_text.lower()

def test_create_calculation_single_input_negative(page: Page, fastapi_server: str):
    """Test creating calculation with only one input fails"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"singleinput_{uuid4()}",
        "email": f"singleinput{uuid4()}@example.com",
        "first_name": "Single",
        "last_name": "Input",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '42')
    page.click('button[type="submit"]')
    
    # Wait for validation
    page.wait_for_timeout(500)
    
    # Check error alert is visible
    error_alert = page.locator('#errorAlert')
    expect(error_alert).not_to_have_class('hidden', timeout=5000)
    
    error_text = page.locator('#errorMessage').text_content()
    # Check for "at least 2" case-insensitively
    assert 'at least 2' in error_text.lower() or 'two' in error_text.lower()

def test_create_calculation_non_numeric_inputs_negative(page: Page, fastapi_server: str):
    """Test creating calculation with non-numeric inputs fails"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"nonnumeric_{uuid4()}",
        "email": f"nonnumeric{uuid4()}@example.com",
        "first_name": "NonNumeric",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', 'abc, def')
    page.click('button[type="submit"]')
    
    # Wait for validation
    page.wait_for_timeout(500)
    
    # Check error alert is visible
    error_alert = page.locator('#errorAlert')
    expect(error_alert).not_to_have_class('hidden', timeout=5000)
    
    error_text = page.locator('#errorMessage').text_content()
    assert 'number' in error_text.lower() or 'valid' in error_text.lower() or 'numeric' in error_text.lower()

def test_create_calculation_division_by_zero_negative(page: Page, fastapi_server: str):
    """Test division by zero is prevented"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"divzero_{uuid4()}",
        "email": f"divzero{uuid4()}@example.com",
        "first_name": "Div",
        "last_name": "Zero",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    page.select_option('select[name="type"]', 'division')
    page.fill('input[name="inputs"]', '100, 0')
    page.click('button[type="submit"]')
    
    # Wait for validation
    page.wait_for_timeout(500)
    
    # Check error alert is visible
    error_alert = page.locator('#errorAlert')
    expect(error_alert).not_to_have_class('hidden', timeout=5000)
    
    error_text = page.locator('#errorMessage').text_content()
    assert 'zero' in error_text.lower() or 'divide' in error_text.lower()

def test_update_calculation_invalid_inputs_negative(page: Page, fastapi_server: str):
    """Test updating calculation with invalid inputs fails"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"invalidupdate_{uuid4()}",
        "email": f"invalidupdate{uuid4()}@example.com",
        "first_name": "Invalid",
        "last_name": "Update",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Create a calculation
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '1, 2, 3')
    page.click('button[type="submit"]')
    page.wait_for_timeout(500)
    
    # Open edit mode - use specific selector for View button in table
    page.locator('table tbody tr').first.locator('.view-calc').click()
    page.click('#editBtn')
    
    # Try to update with single input
    page.fill('#modalInputs', '42')
    page.click('#saveBtn')
    
    # Wait for validation
    page.wait_for_timeout(500)
    
    # Check error alert is visible
    error_alert = page.locator('#errorAlert')
    expect(error_alert).not_to_have_class('hidden', timeout=5000)
    
    error_text = page.locator('#errorMessage').text_content()
    assert 'at least 2' in error_text.lower() or 'two' in error_text.lower()

# ==============================================================================
# NEGATIVE TESTS - Unauthorized Access
# ==============================================================================

def test_access_dashboard_without_auth_negative(page: Page, fastapi_server: str):
    """Test accessing dashboard without authentication"""
    base_url = fastapi_server.rstrip("/")
    
    # First navigate to a page on the domain to enable localStorage access
    page.goto(f"{base_url}/login")
    
    # Clear any existing storage
    page.context.clear_cookies()
    page.evaluate("() => localStorage.clear()")
    
    # Try to access dashboard directly
    page.goto(f"{base_url}/dashboard")
    
    # Should be redirected to login
    page.wait_for_url(f"{base_url}/login", timeout=5000)

def test_create_calculation_expired_token_negative(page: Page, fastapi_server: str):
    """Test that operations fail with expired/invalid token"""
    base_url = fastapi_server.rstrip("/")
    
    # First navigate to dashboard page to get on the domain
    page.goto(f"{base_url}/dashboard")
    
    # Wait briefly for any redirect
    page.wait_for_timeout(500)
    
    # Now we should be on login page or dashboard
    # Navigate to login page first to set up localStorage
    page.goto(f"{base_url}/login")
    page.wait_for_load_state('networkidle')
    
    # Set invalid token
    page.evaluate("() => localStorage.setItem('access_token', 'invalid_token_123')")
    
    # Now go to dashboard
    page.goto(f"{base_url}/dashboard")
    page.wait_for_load_state('networkidle')
    
    # The page should either redirect to login or show error when trying to use API
    # Wait for potential redirect
    page.wait_for_timeout(2000)
    current_url = page.url
    
    # Either should be on login page, or if on dashboard, API calls should fail
    if '/login' not in current_url:
        # We're on dashboard, try to create calculation
        # Check if the form elements are present
        type_select = page.locator('select[name="type"]')
        if type_select.is_visible():
            page.select_option('select[name="type"]', 'addition')
            page.fill('input[name="inputs"]', '1, 2')
            page.click('button[type="submit"]')
            
            # Should redirect to login or show error
            page.wait_for_timeout(2000)
            current_url = page.url
            error_visible = page.locator('#errorAlert').is_visible()
            assert '/login' in current_url or error_visible
    else:
        # Already redirected to login - test passes
        assert '/login' in current_url

# ==============================================================================
# EDGE CASES
# ==============================================================================

def test_create_calculation_large_numbers(page: Page, fastapi_server: str):
    """Test calculation with very large numbers"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"largenums_{uuid4()}",
        "email": f"largenums{uuid4()}@example.com",
        "first_name": "Large",
        "last_name": "Numbers",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Create calculation with large numbers
    page.select_option('select[name="type"]', 'multiplication')
    page.fill('input[name="inputs"]', '999999, 888888')
    page.click('button[type="submit"]')
    
    # Should succeed
    expect(page.locator('#successAlert')).to_be_visible(timeout=5000)
    expect(page.locator('table tbody tr')).to_have_count(1)

def test_create_calculation_decimal_numbers(page: Page, fastapi_server: str):
    """Test calculation with decimal numbers"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"decimals_{uuid4()}",
        "email": f"decimals{uuid4()}@example.com",
        "first_name": "Decimal",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '1.5, 2.3, 3.7')
    page.click('button[type="submit"]')
    
    # Should succeed
    expect(page.locator('#successAlert')).to_be_visible(timeout=5000)
    expect(page.locator('table tbody tr:first-child')).to_contain_text('7.5')

def test_create_calculation_negative_numbers(page: Page, fastapi_server: str):
    """Test calculation with negative numbers"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"negative_{uuid4()}",
        "email": f"negative{uuid4()}@example.com",
        "first_name": "Negative",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '-10, 5, -3')
    page.click('button[type="submit"]')
    
    # Should succeed
    expect(page.locator('#successAlert')).to_be_visible(timeout=5000)
    expect(page.locator('table tbody tr:first-child')).to_contain_text('-8')

def test_refresh_calculations_list(page: Page, fastapi_server: str):
    """Test refresh button updates calculation list"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"refresh_{uuid4()}",
        "email": f"refresh{uuid4()}@example.com",
        "first_name": "Refresh",
        "last_name": "Test",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Create a calculation
    page.select_option('select[name="type"]', 'addition')
    page.fill('input[name="inputs"]', '1, 2')
    page.click('button[type="submit"]')
    page.wait_for_timeout(500)
    
    # Click refresh
    page.click('#refreshBtn')
    
    # Should see success message
    expect(page.locator('#successAlert')).to_be_visible(timeout=5000)
    expect(page.locator('#successMessage')).to_contain_text('refreshed')

def test_clear_form_button(page: Page, fastapi_server: str):
    """Test clear button resets form"""
    base_url = fastapi_server.rstrip("/")
    user_data = {
        "username": f"clearform_{uuid4()}",
        "email": f"clearform{uuid4()}@example.com",
        "first_name": "Clear",
        "last_name": "Form",
        "password": "TestPass123!"
    }
    
    register_and_login_ui(page, base_url, user_data)
    
    # Fill form
    page.select_option('select[name="type"]', 'multiplication')
    page.fill('input[name="inputs"]', '5, 10, 15')
    
    # Click clear
    page.click('#clearBtn')
    
    # Verify form is cleared
    assert page.locator('select[name="type"]').input_value() == ''
    assert page.locator('input[name="inputs"]').input_value() == ''