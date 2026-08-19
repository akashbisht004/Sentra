export function durationToDate(duration: string): Date {
    const match = duration.match(/^(\d+)([dhm])$/i);

    if (!match) {
        throw new Error("Invalid duration");
    }

    const value = Number(match[1]);
    const unit = match[2]!.toLowerCase();

    const multipliers = {
        d: 24 * 60 * 60 * 1000,
        h: 60 * 60 * 1000,
        m: 60 * 1000
    };

    const milliseconds =
        value * multipliers[unit as keyof typeof multipliers];

    return new Date(Date.now() + milliseconds);
}


