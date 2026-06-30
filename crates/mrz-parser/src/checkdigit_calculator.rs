//!
//! The original implementation used a static class with a private constructor and
//! a static method `getCheckDigit(String input)`. Here we provide a simple
//! function `get_check_digit` that computes the MRZ check digit for an input
//! string using weights [7, 3, 1] and the standard MRZ character mapping:
//! - 'A'..'Z' -> 10..35
//! - '0'..'9' -> 0..9
//! - anything else -> 0
//!
//! Returns the check digit as `u8` in range 0..=9.
const WEIGHTS: [usize; 3] = [7, 3, 1];

/// Compute the MRZ check digit for `input`.
///
/// The algorithm:
/// 1. For each character, map it to a numeric value:
///    - 'A'..'Z' -> 10 + (ch - 'A')
///    - '0'..'9' -> ch - '0'
///    - otherwise -> 0
/// 2. Multiply each value by the repeating weights [7,3,1] at its index.
/// 3. Sum the products and return (sum % 10) as the check digit.
///
/// Example:
/// ```
/// assert_eq!(mrz_parser::get_check_digit("L898902C3"), 6);
/// ```
pub fn get_check_digit(input: &str) -> u8 {
    // Use bytes for ASCII MRZ content; MRZ should only contain ASCII characters.
    let sum: usize = input
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let value = if is_capital_letter(b) {
                // 'A' => 10
                (b - b'A') as usize + 10
            } else if is_digit(b) {
                (b - b'0') as usize
            } else {
                0
            };
            value * WEIGHTS[i % WEIGHTS.len()]
        })
        .sum();

    (sum % 10) as u8
}

#[inline]
fn is_capital_letter(b: u8) -> bool {
    b >= b'A' && b <= b'Z'
}

#[inline]
fn is_digit(b: u8) -> bool {
    b >= b'0' && b <= b'9'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_letters_and_digits() {
        // From examples commonly used in MRZ docs:
        // For "L898902C3" the computed check digit should be 6.
        assert_eq!(get_check_digit("L898902C3"), 6);

        // Single digits: value × weight[0] (7) % 10
        // "0" => 0*7=0 => 0
        // "1" => 1*7=7 => 7
        // "9" => 9*7=63 => 3
        assert_eq!(get_check_digit("0"), 0);
        assert_eq!(get_check_digit("1"), 7);
        assert_eq!(get_check_digit("9"), 3);

        // Letters mapping: 'A' -> 10, weight 7 -> 70 -> 0 (70 % 10 == 0)
        assert_eq!(get_check_digit("A"), 0);

        // Mixed example
        // Compute manually for verification:
        // characters: 'M' (22), 'R' (27), 'Z' (35), '1' (1), '2' (2)
        // weights:   7, 3, 1, 7, 3
        // products: 154, 81, 35, 7, 6 => sum = 283 => 283 % 10 = 3
        assert_eq!(get_check_digit("MRZ12"), 3);
    }

    #[test]
    fn test_non_mrz_chars_treated_as_zero() {
        // Characters outside A-Z and 0-9 are treated as 0 (e.g. '<')
        // Example: "<" => 0 -> weighted 7 -> 0 mod 10
        assert_eq!(get_check_digit("<"), 0);

        // Mix of valid and fillers
        assert_eq!(get_check_digit("ABC<123"), {
            // Manual verification:
            // 'A'(10)*7 = 70
            // 'B'(11)*3 = 33
            // 'C'(12)*1 = 12
            // '<'(0)*7 = 0
            // '1'(1)*3 = 3
            // '2'(2)*1 = 2
            // '3'(3)*7 = 21
            // sum = 70+33+12+0+3+2+21 = 141 => 141 % 10 = 1
            1
        });
    }

    #[test]
    fn test_long_input() {
        let s = "L898902C360X"; // arbitrary sequence
                                // Ensure function runs and returns a digit
        let d = get_check_digit(s);
        assert!(d <= 9);
    }
}
