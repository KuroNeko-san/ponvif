<?php

require('vendor/autoload.php');

return \PhpCsFixer\Config::create()
    ->setRules([
        '@PSR2' => true,

        'array_syntax' => [
            'syntax' => 'short', // PHP arrays should use the PHP 5.4 short-syntax.
        ],
        'binary_operator_spaces' => [
            'align_double_arrow' => true, // Align double arrow symbols in consecutive lines.
            'align_equals'       => true, // Align equals symbols in consecutive lines.
        ],
        'blank_line_after_opening_tag'          => true, // Ensure there is no code on the same line as the PHP open tag and it is followed by a blankline.
        'blank_line_before_return'              => true, // An empty line feed should precede a return statement.
        'concat_space' => [
            'spacing' => 'one', // Concatenation should be used with at least one whitespace around.
        ],
        'no_closing_tag'                        => true,
        'braces'                                => true,
        'cast_spaces'                           => true,
        'new_with_braces'                       => true, // All instances created with new keyword must be followed by braces.
        'no_extra_consecutive_blank_lines'      => [
            'extra', // Removes extra empty lines.
            'use',   // Removes extra empty lines between uses.
        ],
        'no_trailing_comma_in_singleline_array' => true, // PHP single-line arrays should not have trailing comma.
        'no_unused_imports'                     => true, // Unused use statements must be removed.
        'no_whitespace_in_blank_line'           => true, // Remove trailing whitespace at the end of blank lines.
        'not_operator_with_successor_space'     => true, // Logical NOT operators (!) should have one trailing whitespace.
        'ordered_imports'                       => true, // Ordering use statements.
        'phpdoc_align'                          => true, // All items of the @param, @throws, @return, @var, and @type phpdoc tags must be aligned vertically.
        'phpdoc_order'                          => true, // Annotations in phpdocs should be ordered so that param annotations come first, then throws annotations, then return annotations.
        'phpdoc_separation'                     => true, // Annotations in phpdocs should be grouped together so that annotations of the same type immediately follow each other, and annotations of a different type are separated by a single blank line.
        'single_quote'                          => true, // Convert double quotes to single quotes for simple strings.
        'standardize_not_equals'                => true, // Replace all <> with !=.
        'trailing_comma_in_multiline_array'     => true, // PHP multi-line arrays should have a trailing comma.
        'single_blank_line_before_namespace'    => true, // There should be exactly one blank line before a namespace declaration.

    ])
    ->setFinder(
        \PhpCsFixer\Finder::create()
            ->in(getcwd())
    );
