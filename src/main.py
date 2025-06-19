#!/usr/bin/env python


from CONSTS import CLOUDS
from modules.clouds.aws import AWSAnalyzer
from modules.cli import CLI


args = CLI().parse_args()

match args.provider:
    case CLOUDS.AWS:
        AWSAnalyzer(
            ports=args.ports,
            output_file=args.output,
            regions=args.aws_regions.split(","),
            enable_logging=args.debug,
        )
