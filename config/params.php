<?php

declare(strict_types=1);

return [
    'yiirocks/voyti' => [
        'api' => [
            'routes' => [
                ...require __DIR__ . '/routes.php',
            ],
        ],
    ],
];
