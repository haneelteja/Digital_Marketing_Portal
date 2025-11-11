/**
 * Input Validation and Sanitization Utilities
 * Provides comprehensive validation for all user inputs
 */

export interface ValidationResult {
  valid: boolean;
  errors: Record<string, string>;
}

export class Validator {
  /**
   * Validate email address
   */
  static email(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate phone number (flexible format)
   */
  static phone(phone: string): boolean {
    const phoneRegex = /^[0-9+()\-\s]{6,20}$/;
    return phoneRegex.test(phone);
  }

  /**
   * Validate UUID
   */
  static uuid(id: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(id);
  }

  /**
   * Validate date string (YYYY-MM-DD)
   */
  static date(dateString: string): boolean {
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(dateString)) return false;
    
    const date = new Date(dateString);
    return date instanceof Date && !isNaN(date.getTime());
  }

  /**
   * Validate date range
   */
  static dateRange(startDate: string, endDate: string): boolean {
    if (!this.date(startDate) || !this.date(endDate)) return false;
    return new Date(startDate) <= new Date(endDate);
  }

  /**
   * Sanitize string input (remove dangerous characters)
   */
  static sanitizeString(input: string, maxLength?: number): string {
    let sanitized = input.trim();
    
    // Remove potentially dangerous characters
    sanitized = sanitized.replace(/[<>]/g, '');
    
    // Limit length if specified
    if (maxLength && sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }
    
    return sanitized;
  }

  /**
   * Validate required field
   */
  static required(value: unknown, fieldName: string): string | null {
    if (value === null || value === undefined || value === '') {
      return `${fieldName} is required`;
    }
    if (typeof value === 'string' && value.trim().length === 0) {
      return `${fieldName} cannot be empty`;
    }
    return null;
  }

  /**
   * Validate string length
   */
  static validateLength(value: string, min: number, max: number, fieldName: string): string | null {
    if (value.length < min) {
      return `${fieldName} must be at least ${min} characters`;
    }
    if (value.length > max) {
      return `${fieldName} must be at most ${max} characters`;
    }
    return null;
  }

  /**
   * Validate number range
   */
  static numberRange(value: number, min: number, max: number, fieldName: string): string | null {
    if (isNaN(value)) {
      return `${fieldName} must be a valid number`;
    }
    if (value < min) {
      return `${fieldName} must be at least ${min}`;
    }
    if (value > max) {
      return `${fieldName} must be at most ${max}`;
    }
    return null;
  }

  /**
   * Validate array
   */
  static array(value: unknown, minLength: number, fieldName: string): string | null {
    if (!Array.isArray(value)) {
      return `${fieldName} must be an array`;
    }
    if (value.length < minLength) {
      return `${fieldName} must have at least ${minLength} item(s)`;
    }
    return null;
  }

  /**
   * Validate campaign data
   */
  static campaign(data: {
    campaign_name?: string;
    start_date?: string;
    end_date?: string;
    target_platforms?: string[];
    budget?: number | string;
    client_id?: string;
    status?: string;
  }): ValidationResult {
    const errors: Record<string, string> = {};

    // Campaign name
    const nameError = this.required(data.campaign_name, 'Campaign name');
    if (nameError) errors.campaign_name = nameError;
    else if (data.campaign_name) {
      const lengthError = this.validateLength(data.campaign_name, 1, 255, 'Campaign name');
      if (lengthError) errors.campaign_name = lengthError;
    }

    // Dates
    const startDateError = this.required(data.start_date, 'Start date');
    if (startDateError) errors.start_date = startDateError;
    else if (data.start_date && !this.date(data.start_date)) {
      errors.start_date = 'Start date must be in YYYY-MM-DD format';
    }

    const endDateError = this.required(data.end_date, 'End date');
    if (endDateError) errors.end_date = endDateError;
    else if (data.end_date && !this.date(data.end_date)) {
      errors.end_date = 'End date must be in YYYY-MM-DD format';
    }

    // Date range validation
    if (data.start_date && data.end_date && this.date(data.start_date) && this.date(data.end_date)) {
      if (!this.dateRange(data.start_date, data.end_date)) {
        errors.end_date = 'End date must be after or equal to start date';
      }
    }

    // Target platforms - now optional (no validation required)

    // Budget - now mandatory
    const budgetError = this.required(data.budget, 'Budget');
    if (budgetError) {
      errors.budget = budgetError;
    } else if (data.budget !== undefined && data.budget !== null && data.budget !== '') {
      const budgetNum = typeof data.budget === 'string' ? parseFloat(data.budget) : data.budget;
      if (isNaN(budgetNum)) {
        errors.budget = 'Budget must be a valid number';
      } else if (budgetNum < 0) {
        errors.budget = 'Budget cannot be negative';
      } else if (budgetNum > 999999999999) {
        errors.budget = 'Budget is too large';
      }
    }

    // Client ID - now mandatory
    const clientIdError = this.required(data.client_id, 'Client');
    if (clientIdError) {
      errors.client_id = clientIdError;
    } else if (data.client_id && !this.uuid(data.client_id)) {
      errors.client_id = 'Invalid client ID format';
    }

    // Status
    const validStatuses = ['draft', 'active', 'completed', 'cancelled'];
    if (data.status && !validStatuses.includes(data.status)) {
      errors.status = `Status must be one of: ${validStatuses.join(', ')}`;
    }

    return {
      valid: Object.keys(errors).length === 0,
      errors,
    };
  }

  /**
   * Validate client data
   */
  static client(data: {
    companyName?: string;
    gstNumber?: string;
    email?: string;
    phoneNumber?: string;
    address?: string;
  }): ValidationResult {
    const errors: Record<string, string> = {};

    const companyNameError = this.required(data.companyName, 'Company name');
    if (companyNameError) errors.companyName = companyNameError;

    const gstError = this.required(data.gstNumber, 'GST number');
    if (gstError) errors.gstNumber = gstError;

    const emailError = this.required(data.email, 'Email');
    if (emailError) {
      errors.email = emailError;
    } else if (data.email && !this.email(data.email)) {
      errors.email = 'Invalid email format';
    }

    const phoneError = this.required(data.phoneNumber, 'Phone number');
    if (phoneError) {
      errors.phoneNumber = phoneError;
    } else if (data.phoneNumber && !this.phone(data.phoneNumber)) {
      errors.phoneNumber = 'Invalid phone number format';
    }

    const addressError = this.required(data.address, 'Address');
    if (addressError) errors.address = addressError;

    return {
      valid: Object.keys(errors).length === 0,
      errors,
    };
  }
}


