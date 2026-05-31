package visual

type nodeStyle struct {
	Fill   string
	Stroke string
	Text   string
}

type edgeStyle struct {
	Color string
	Text  string
	Width string
}

func styleForRole(role Role) nodeStyle {
	switch role {
	case RoleChanged:
		return nodeStyle{Fill: "#fff7ed", Stroke: "#f97316", Text: "#7c2d12"}
	case RolePublic:
		return nodeStyle{Fill: "#eff6ff", Stroke: "#2563eb", Text: "#1e3a8a"}
	case RoleWorkload:
		return nodeStyle{Fill: "#ecfeff", Stroke: "#0891b2", Text: "#164e63"}
	case RoleSensitive:
		return nodeStyle{Fill: "#fef2f2", Stroke: "#dc2626", Text: "#7f1d1d"}
	case RolePrincipal:
		return nodeStyle{Fill: "#f5f3ff", Stroke: "#7c3aed", Text: "#3b0764"}
	case RolePolicy:
		return nodeStyle{Fill: "#fdf4ff", Stroke: "#c026d3", Text: "#701a75"}
	case RoleNetwork:
		return nodeStyle{Fill: "#f0fdf4", Stroke: "#16a34a", Text: "#14532d"}
	case RolePath:
		return nodeStyle{Fill: "#eef2ff", Stroke: "#4f46e5", Text: "#312e81"}
	case RoleBlock:
		return nodeStyle{Fill: "#fee2e2", Stroke: "#b91c1c", Text: "#7f1d1d"}
	case RoleWarn:
		return nodeStyle{Fill: "#fef3c7", Stroke: "#d97706", Text: "#78350f"}
	case RoleAllow:
		return nodeStyle{Fill: "#dcfce7", Stroke: "#16a34a", Text: "#14532d"}
	case RoleInternet:
		return nodeStyle{Fill: "#e0f2fe", Stroke: "#0284c7", Text: "#0c4a6e"}
	default:
		return nodeStyle{Fill: "#f8fafc", Stroke: "#94a3b8", Text: "#0f172a"}
	}
}

func edgeStyleForRole(role Role) edgeStyle {
	switch role {
	case RoleBlock:
		return edgeStyle{Color: "#b91c1c", Text: "#7f1d1d", Width: "2.4"}
	case RoleWarn:
		return edgeStyle{Color: "#d97706", Text: "#78350f", Width: "2.2"}
	case RoleAllow:
		return edgeStyle{Color: "#16a34a", Text: "#14532d", Width: "2"}
	case RolePath:
		return edgeStyle{Color: "#4f46e5", Text: "#312e81", Width: "2.4"}
	default:
		return edgeStyle{Color: "#64748b", Text: "#475569", Width: "1.4"}
	}
}
